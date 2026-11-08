// Simple page changes and requests to our Flask app.
const $ = (id) => document.getElementById(id);
let historyItems = [];
let currentResult = null;
let filter = 'all';
let visibleRows = 9;
let requestNumber = 0;
let controller = null;
const labels = {high: 'High risk', caution: 'Be careful', low: 'Low risk'};
const iconPaths = {link:'M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-2 2M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l2-2',search:'M21 21l-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',shield:'M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6ZM8 12l3 3 5-6'};
function icon(name) {return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${iconPaths[name] || iconPaths.search}"/></svg>`;}
document.querySelectorAll('[data-icon]').forEach(el => el.innerHTML = icon(el.dataset.icon));

// Input URLs are always added as text, never as HTML or clickable links.
function element(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}
function badge(item) {return element('span', labels[item.risk], `badge ${item.risk}`);}
function checkedTime(item) {return new Date(item.checked_at).toLocaleString([], {dateStyle:'short',timeStyle:'short'});}
function showPage(name) {
  document.querySelectorAll('.view').forEach(el => el.hidden = el.id !== name);
  document.querySelectorAll('nav a').forEach(a => {
    if (a.hash === '#' + name) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  window.scrollTo(0, 0);
  // Move keyboard focus to the new page so the result is announced.
  const target = document.getElementById(name).querySelector('h1') || document.getElementById(name);
  target.setAttribute('tabindex', '-1');
  target.focus({preventScroll:true});
}
function route() {
  const hash = location.hash.slice(1) || 'home';
  if (hash === 'history') {showPage('history'); renderHistory();}
  else if (hash === 'result' && currentResult) {showPage('result');}
  else {showPage('home'); if (hash === 'how') $('how').scrollIntoView({behavior:'auto'});}
}
window.addEventListener('hashchange', route);
async function loadHistory() {
  const response = await fetch('/api/history');
  if (!response.ok) throw new Error('History could not be loaded. Refresh to try again.');
  historyItems = await response.json();
  renderRecent(); renderHistory();
}
function openResult(item) {
  currentResult = item;
  const titles = {high:'High risk — we’d avoid this one',caution:'Be careful with this link',low:'Low risk — still check before opening'};
  $('result-title').textContent = titles[item.risk];
  $('risk-banner').className = item.risk;
  $('score').textContent = `${item.trust_score}/100`;
  $('result-subtitle').textContent = `Trust score ${item.trust_score}/100 · ${item.observations.length} URL observations`;
  $('result-url').textContent = item.url;
  $('model-explanation').textContent = `The trained model classified this URL as ${item.prediction}. Its estimated phishing score is ${(item.phishing_probability * 100).toFixed(1)}%. ${item.model_version === 'url-tree-v2' ? '' : 'This is a saved result from the older model. Check this URL again for the updated score.'}`;
  $('observations').replaceChildren();
  if (!item.observations.length) $('observations').append(element('p','No extra structural warning signs were found by our simple checks. The model can still make mistakes.'));
  item.observations.forEach(note => {
    const row = element('div', undefined, 'observation');
    const symbol = element('span',undefined,'step-icon'); symbol.innerHTML = icon('search');
    const text = element('div'); text.append(element('h3',note.title),element('p',note.text));
    row.append(symbol,text); $('observations').append(row);
  });
  $('feature-list').replaceChildren();
  Object.entries(item.features).forEach(([name,value]) => {
    $('feature-list').append(element('dt',name.replaceAll('_',' ')),element('dd',Number.isInteger(value)?value:Number(value).toFixed(3)));
  });
  const advice = item.risk === 'low' ? ['Check the real hostname before opening the link.','Use an official app or a known bookmark for sensitive accounts.','Do not rely on this score alone.'] : ['Avoid opening the link until you confirm who sent it.','Do not enter passwords or personal information.','Use the organisation’s official app or a known bookmark instead.'];
  $('advice').replaceChildren(...advice.map(text => element('li',text)));
  $('report').disabled = item.reported;
  $('report').textContent = item.reported ? 'Saved for review' : 'Report this result';
  $('action-message').textContent = '';
  location.hash = 'result'; showPage('result');
}
function renderRecent() {
  $('recent-list').replaceChildren();
  if (!historyItems.length) {$('recent-list').append(element('p','No links checked yet. Paste one above to get started.','empty'));return;}
  historyItems.slice(0,3).forEach(item => {
    const row = element('button',undefined,'recent-row');
    row.append(element('span',item.url,'recent-url mono'),element('span',checkedTime(item),'small-date'),badge(item),element('span','›'));
    row.addEventListener('click',()=>openResult(item)); $('recent-list').append(row);
  });
}
function renderHistory() {
  $('history-counts').replaceChildren();
  $('history-counts').append(element('span',`${historyItems.length} links checked`));
  ['high','low','caution'].forEach(risk => $('history-counts').append(element('span',`${historyItems.filter(i=>i.risk===risk).length} ${labels[risk].toLowerCase()}`)));
  const search = $('search').value.toLowerCase();
  const items = historyItems.filter(i => (filter==='all'||i.risk===filter) && (i.url.toLowerCase().includes(search)||labels[i.risk].toLowerCase().includes(search)));
  $('history-rows').replaceChildren();
  items.slice(0,visibleRows).forEach(item => {
    const row = element('tr'); const url = element('td',item.url,'mono'); url.title=item.url;
    const verdict = element('td');verdict.append(badge(item));
    const button = element('button','›','open-result');button.setAttribute('aria-label',`Open result for ${item.url}`);button.addEventListener('click',()=>openResult(item));
    const action = element('td');action.append(button);
    row.append(url,verdict,element('td',`${item.trust_score}/100`),element('td',checkedTime(item),'small-date'),action);$('history-rows').append(row);
  });
  $('history-empty').hidden=items.length>0;
  $('history-empty').textContent=historyItems.length?'No links match this filter.':'No links checked yet. Paste one on the Check a link page.';
  $('load-more').hidden=items.length<=visibleRows;
}
$('search').addEventListener('input',()=>{visibleRows=9;renderHistory();});
$('filters').addEventListener('click',event=>{
  const button=event.target.closest('[data-filter]');if(!button)return;
  filter=button.dataset.filter;visibleRows=9;
  document.querySelectorAll('[data-filter]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));renderHistory();
});
$('load-more').addEventListener('click',()=>{visibleRows+=9;renderHistory();});
$('check-form').addEventListener('submit',async event=>{
  event.preventDefault(); $('form-error').textContent='';
  const url=$('url-input').value.trim();
  if(!url){$('form-error').textContent='Please paste a website address.';return;}
  const number=++requestNumber;controller=new AbortController();
  $('loading-url').textContent=url;showPage('loading');
  try{
    const response=await fetch('/api/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url}),signal:controller.signal});
    const result=await response.json();
    if(number!==requestNumber)return;
    if(!response.ok)throw new Error(result.error||'The check failed. Please try again.');
    historyItems.unshift(result);renderRecent();renderHistory();openResult(result);
  }catch(error){
    if(number!==requestNumber||error.name==='AbortError')return;
    showPage('home');$('form-error').textContent=error.message;$('url-input').focus();
  }
});
$('cancel').addEventListener('click',()=>{
  ++requestNumber;controller?.abort();showPage('home');$('url-input').focus();
  // A request already processed by the server can still appear in history.
  loadHistory().catch(()=>{});
});
$('another').addEventListener('click',()=>{location.hash='home';showPage('home');$('url-input').focus();});
$('report').addEventListener('click',async()=>{
  if(!currentResult)return;
  $('report').disabled=true;
  try{
    const response=await fetch(`/api/report/${currentResult.id}`,{method:'POST'});const data=await response.json();
    if(!response.ok)throw new Error(data.error||'Could not save this report.');
    currentResult.reported=true;$('report').textContent='Saved for review';$('action-message').textContent=data.message;
  }catch(error){$('report').disabled=false;$('action-message').textContent=error.message;}
});
$('copy').addEventListener('click',async()=>{
  if(!currentResult)return;
  try{await navigator.clipboard.writeText(`Link Check: ${labels[currentResult.risk]}\n${currentResult.url}\nTrust score: ${currentResult.trust_score}/100\nModel estimate only; the website was not visited.`);$('action-message').textContent='Summary copied.';}
  catch{$('action-message').textContent='Copy is unavailable in this browser. Select the result text to copy it.';}
});
$('privacy').addEventListener('click',()=>{
  $('notice').textContent='This local app stores the pasted URL, its features, and the result in SQLite for history. Nothing is sent to an external service. Avoid pasting links with private tokens. History is separated by browser cookie.';
  $('notice').hidden=!$('notice').hidden;
});
route();loadHistory().catch(error=>{$('form-error').textContent=error.message;});

$('recheck').addEventListener('click',()=>{if(currentResult){$('url-input').value=currentResult.url;$('check-form').requestSubmit();}});
