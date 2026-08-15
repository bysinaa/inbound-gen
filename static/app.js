let session = "";
let trustedFingerprint = "";
const $ = id => document.getElementById(id);

async function post(path, data) {
  const response = await fetch(path, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(data)});
  const body = await response.json();
  if (!response.ok && response.status !== 409) throw new Error(body.error || "خطای ناشناخته");
  return {status:response.status, body};
}

function credentials() {
  return {host:$("host").value.trim(), port:Number($("sshPort").value), username:$("username").value.trim(), password:$("password").value, fingerprint:trustedFingerprint};
}

async function detect() {
  const button=$("detectButton"), status=$("detectStatus"); button.disabled=true; status.textContent="در حال اتصال SSH و جستجوی پنل…";
  try {
    const result=await post("/api/detect",credentials());
    if(result.status===409){trustedFingerprint=result.body.fingerprint;$("fingerprint").textContent=trustedFingerprint;$("trustBox").classList.remove("hidden");status.textContent="ابتدا fingerprint را تأیید کن.";return;}
    session=result.body.session;$("trustBox").classList.add("hidden");$("connectionBadge").textContent=`متصل: ${$("host").value}`;$("connectionBadge").className="badge ok";
    $("smartCard").classList.remove("disabled");$("buildCard").classList.remove("disabled");$("listCard").classList.remove("disabled");
    const facts=$("serverFacts"); facts.innerHTML=`<div><small>3x-ui</small>${escapeHtml(result.body.version||"تشخیص داده شد")}</div><div><small>Xray</small>${escapeHtml(result.body.xray_version||"-")}</div><div><small>Certificate</small>${result.body.certificates.length} فایل پیدا شد</div>`;facts.classList.remove("hidden");
    renderInbounds(result.body.inbounds); status.textContent="پنل و API با موفقیت تشخیص داده شد.";
  } catch(e){status.textContent=e.message;} finally {button.disabled=false;}
}

function escapeHtml(value){return String(value).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function renderInbounds(items){$("inboundRows").innerHTML=items.map(x=>`<tr><td>${escapeHtml(x.remark)}</td><td>${escapeHtml(x.protocol)}</td><td>${x.port}</td><td class="${x.enable?'on':'off'}">${x.enable?'فعال':'خاموش'}</td></tr>`).join("");}

function templateChanged(){const value=$("template").value,tls=value.includes("tls"),reality=value.includes("reality"),xhttp=value.includes("xhttp");document.querySelectorAll(".tls").forEach(x=>x.classList.toggle("hidden",!tls));document.querySelectorAll(".reality").forEach(x=>x.classList.toggle("hidden",!reality));document.querySelectorAll(".xhttp").forEach(x=>x.classList.toggle("hidden",!xhttp));}

async function createTest(){const button=$("createButton"),status=$("createStatus"),result=$("result");button.disabled=true;status.textContent="ساخت inbound، دریافت لینک و سه تست دانلود/آپلود…";result.classList.add("hidden");
  const data={session,template:$("template").value,remark:$("remark").value.trim(),inbound_port:Number($("inboundPort").value),address:$("address").value.trim(),host:$("hostHeader").value.trim(),sni:$("sni").value.trim(),path:$("path").value,fingerprint:$("fp").value,certificate:$("certificate").value.trim(),private_key:$("privateKey").value.trim(),reality_target:$("realityTarget").value.trim(),mode:$("mode").value};
  try{const response=await post("/api/create-test",data),x=response.body;const firewall={"ufw-added":"UFW باز شد","ufw-open":"UFW از قبل باز بود","firewalld-added":"firewalld باز شد","firewalld-open":"firewalld از قبل باز بود","no-active-firewall":"فایروال فعالی پیدا نشد"}[x.firewall]||x.firewall;result.className=`result ${x.working?'ok':'fail'}`;result.innerHTML=`<strong>${x.working?'موفق':'ناموفق'}</strong><p>${escapeHtml(x.remark)} · ${escapeHtml(x.protocol)} · پورت ${x.port}${x.port_automatic?' (انتخاب خودکار)':''}</p><p>${escapeHtml(firewall)} · پایداری: ${x.stability}${x.disabled_after_failure?' · inbound غیرفعال شد و Rule جدید برگشت خورد':''}</p>`;result.classList.remove("hidden");status.textContent="تست تمام شد.";await refresh();}catch(e){status.textContent=e.message;}finally{button.disabled=false;}
}
async function refresh(){if(!session)return;try{const x=await post("/api/inbounds",{session});renderInbounds(x.body.inbounds);}catch(e){$("createStatus").textContent=e.message;}}

async function smartBuild(){const button=$("smartButton"),status=$("smartStatus"),result=$("smartResult");button.disabled=true;status.textContent="در حال تشخیص دامنه، دریافت SSL و امتحان ترکیب‌ها…";result.classList.add("hidden");
  try{const response=await post("/api/smart-build",{session,domains:$("smartDomains").value,clean_addresses:$("cleanAddresses").value,fingerprint:$("fp").value}),items=response.body.results;const ok=items.some(x=>x.working);result.className=`result ${ok?'ok':'fail'}`;result.innerHTML=items.map(x=>`<strong>${escapeHtml(x.domain)} · ${x.kind==='direct'?'Direct':'CDN'} · ${x.working?'موفق':'ناموفق'}</strong>${x.certificate?'<p>SSL دریافت شد.</p>':x.certificate_error?`<p>SSL: ${escapeHtml(x.certificate_error)}</p>`:''}<ul>${x.attempts.map(a=>`<li>${escapeHtml(a.template)} · ${escapeHtml(a.address)}${a.port?' · '+a.port:''} · ${a.working?'موفق '+escapeHtml(a.stability||''):escapeHtml(a.error||'ناموفق')}</li>`).join('')}</ul>`).join('');result.classList.remove("hidden");status.textContent="ماتریس هوشمند تمام شد.";await refresh();}catch(e){status.textContent=e.message;}finally{button.disabled=false;}
}

$("detectButton").addEventListener("click",detect);$("trustButton").addEventListener("click",detect);$("template").addEventListener("change",templateChanged);$("createButton").addEventListener("click",createTest);$("smartButton").addEventListener("click",smartBuild);$("refreshButton").addEventListener("click",refresh);templateChanged();
