"""Train the classifier and explore patterns in phishing URLs."""
from pathlib import Path
import json
import joblib
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.dummy import DummyClassifier
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, ConfusionMatrixDisplay
from features import make_features, get_host

ROOT = Path(__file__).resolve().parent


def get_scores(y, predictions):
    return {'accuracy': accuracy_score(y, predictions),
            'precision': precision_score(y, predictions, zero_division=0),
            'recall': recall_score(y, predictions, zero_division=0),
            'f1': f1_score(y, predictions, zero_division=0)}


def new_tree():
    # Limit the size so the tree is easier to explain and less likely to overfit.
    return DecisionTreeClassifier(max_depth=6, min_samples_leaf=20, random_state=42)


def train():
    data = pd.read_csv(ROOT / 'data/urls.csv')
    X = make_features(data['url'])
    y = data['label']
    (ROOT / 'results').mkdir(exist_ok=True)
    (ROOT / 'models').mkdir(exist_ok=True)
    # Split before fitting. Test rows are never used to train this model.
    train_ids, test_ids = train_test_split(data.index, test_size=0.2, stratify=y, random_state=42)
    model = new_tree()
    model.fit(X.loc[train_ids], y.loc[train_ids])
    predictions = model.predict(X.loc[test_ids])
    baseline = DummyClassifier(strategy='most_frequent')
    baseline.fit(X.loc[train_ids], y.loc[train_ids])
    scores = {'baseline_random_test': get_scores(y.loc[test_ids], baseline.predict(X.loc[test_ids])),
              'tree_random_train': get_scores(y.loc[train_ids], model.predict(X.loc[train_ids])),
              'tree_random_test': get_scores(y.loc[test_ids], predictions)}
    joblib.dump({'model': model, 'features': list(X.columns)}, ROOT / 'models/classifier.joblib')
    splits = data[['url', 'label']].copy()
    splits['split'] = 'train'
    splits.loc[test_ids, 'split'] = 'test'
    splits.to_csv(ROOT / 'results/split.csv', index=False)
    # Harder check: an exact hostname cannot appear in both parts.
    # Related subdomains may still overlap. This is not a registrable-domain split.
    groups = data['url'].map(get_host)
    hard_train, hard_test = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42).split(X, y, groups))
    assert set(groups.iloc[hard_train]).isdisjoint(set(groups.iloc[hard_test]))
    hard_model = new_tree()
    hard_model.fit(X.iloc[hard_train], y.iloc[hard_train])
    scores['tree_unseen_hostname_test'] = get_scores(y.iloc[hard_test], hard_model.predict(X.iloc[hard_test]))
    # Check each source separately because their URL styles differ.
    provenance = pd.read_csv(ROOT / 'data/provenance.csv')
    assert provenance['url'].equals(data['url'])
    source_scores = {}
    test_predictions = pd.Series(predictions, index=test_ids)
    for source in provenance['source'].unique():
        ids = [i for i in test_ids if provenance.loc[i, 'source'] == source]
        source_scores[source] = get_scores(y.loc[ids], test_predictions.loc[ids])
    (ROOT / 'results/source_metrics.json').write_text(json.dumps(source_scores, indent=2))
    (ROOT / 'results/metrics.json').write_text(json.dumps(scores, indent=2))
    errors = data.loc[test_ids].copy()
    errors['prediction'] = predictions
    errors = errors[errors['label'] != errors['prediction']]
    errors['error_type'] = errors['label'].map({0: 'false_positive', 1: 'false_negative'})
    errors.to_csv(ROOT / 'results/errors.csv', index=False)
    errors.groupby('error_type').head(5).to_csv(ROOT / 'results/error_examples.csv', index=False)
    ConfusionMatrixDisplay.from_predictions(y.loc[test_ids], predictions, display_labels=['Benign', 'Phishing'])
    plt.title('Decision Tree on the test set')
    plt.tight_layout()
    plt.savefig(ROOT / 'results/confusion_matrix.png', dpi=160)
    plt.close()
    importance = pd.Series(model.feature_importances_, index=X.columns).sort_values()
    importance.plot.barh()
    plt.xlabel('Feature importance')
    plt.tight_layout()
    plt.savefig(ROOT / 'results/feature_importance.png', dpi=160)
    plt.close()
    (ROOT / 'results/tree_rules.txt').write_text(export_text(model, feature_names=list(X.columns)))
    # Only training phishing rows enter clustering. The label is not a feature.
    phishing_ids = [i for i in train_ids if y.loc[i] == 1]
    phishing_X = X.loc[phishing_ids]
    scaler = StandardScaler()
    scaled = scaler.fit_transform(phishing_X)
    cluster_model = KMeans(n_clusters=3, n_init=10, random_state=42)
    clusters = cluster_model.fit_predict(scaled)
    joblib.dump({'model': cluster_model, 'scaler': scaler, 'features': list(X.columns)}, ROOT / 'models/clusters.joblib')
    members = data.loc[phishing_ids].copy()
    members['cluster'] = clusters
    members.to_csv(ROOT / 'results/cluster_members.csv', index=False)
    members.groupby('cluster').head(3).to_csv(ROOT / 'results/cluster_examples.csv', index=False)
    members.groupby(['cluster', 'label']).size().rename('count').to_csv(ROOT / 'results/cluster_labels.csv')
    means = phishing_X.assign(cluster=clusters).groupby('cluster').mean()
    means.to_csv(ROOT / 'results/cluster_means.csv')
    phishing_X.mean().to_csv(ROOT / 'results/phishing_feature_means.csv', header=['mean'])
    # Compare in standard deviation units so long features do not dominate.
    differences = pd.DataFrame(scaled, columns=X.columns).assign(cluster=clusters).groupby('cluster').mean()
    notes = ['These groups describe training phishing URLs only. All their labels are 1.']
    for cluster, values in differences.iterrows():
        top = values.abs().nlargest(3).index
        notes.append(f'Cluster {cluster}: {int((clusters == cluster).sum())} URLs.')
        for feature in top:
            direction = 'higher' if values[feature] > 0 else 'lower'
            notes.append(f'  {feature}: {direction} than the phishing average ({values[feature]:.2f} standard deviations).')
    notes.append('Inspect cluster_examples.csv before giving each group a descriptive name.')
    (ROOT / 'results/cluster_notes.txt').write_text('\n'.join(notes))
    print(json.dumps(scores, indent=2))


if __name__ == '__main__':
    train()
