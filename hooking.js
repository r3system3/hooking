// HOOKING - MCProfileEvents / MCSettingsEvents Scanner

const APP_NAME = "HOOKING"
const CREDIT = "SANTOS e r3"
const DISCORD = "discord.gg/hooking"

const PROXY_RULES = [
  { name: "Zeex free/vip", prefixes: ["78f", "d14"] },
  { name: "Desconhecida", prefixes: ["84", "7d", "60a", "051", "3c4", "ae7", "0af", "proxyady", "704", "0d", "40e", "59ac"] },
  { name: "Fatality bypass", prefixes: ["1ea", "b0", "2c", "9d"] },
  { name: "Luxe cheats nova att", prefixes: ["b9", "a4"] },
  { name: "XTREMO", prefixes: ["com.xtremo.mobile"] },
  { name: "Dash", prefixes: ["70a", "dash.proxy"] },
  { name: "eaysff", prefixes: ["60af"] },
  { name: "brisado", prefixes: ["a4c"] }
]

async function alertMsg(title, message) {
  let a = new Alert()
  a.title = title
  a.message = message
  a.addAction("OK")
  await a.present()
}

function isTargetFile(path) {
  let p = path.toLowerCase()
  return (
    p.includes("mcprofile") ||
    p.includes("mcprofileevents") ||
    p.includes("profileevents") ||
    p.includes("mcsetting") ||
    p.includes("mcsettingsevents") ||
    p.includes("settingsevents")
  )
}

function getSource(path, text) {
  let p = path.toLowerCase()
  let t = text.toLowerCase()

  if (p.includes("setting") || t.includes("systemsettings") || t.includes("systemprofilerestrictions")) {
    return "MCSettingsEvents"
  }

  if (p.includes("profile") || t.includes("profileevents")) {
    return "MCProfileEvents"
  }

  return "MCEvents"
}

function walkDirectory(fm, dir, files = []) {
  for (let item of fm.listContents(dir)) {
    let path = fm.joinPath(dir, item)

    if (fm.isDirectory(path)) {
      walkDirectory(fm, path, files)
    } else if (isTargetFile(path)) {
      files.push(path)
    }
  }

  return files
}

function readFileText(fm, path) {
  try {
    return fm.readString(path)
  } catch (e) {
    return ""
  }
}

function normalizeText(text) {
  return String(text || "")
    .replace(/\u0000/g, "")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, " ")
    .replace(/\s+/g, " ")
}

function cleanCode(code) {
  return String(code || "")
    .replace(/^[^a-zA-Z0-9]+/, "")
    .replace(/[^a-zA-Z0-9._~\-]+$/, "")
    .trim()
}

function detectProxyOwner(code) {
  let lower = String(code || "").toLowerCase()

  for (let rule of PROXY_RULES) {
    for (let prefix of rule.prefixes) {
      if (lower.startsWith(prefix.toLowerCase())) {
        return rule.name
      }
    }
  }

  return null
}

function classifyCode(code) {
  let lower = code.toLowerCase()

  if (/^[a-f0-9]{32,128}-[a-f0-9-]{20,80}$/i.test(code)) return "Hash + UUID"
  if (/^[a-f0-9]{32,128}$/i.test(code)) return "Hash"
  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(code)) return "UUID"
  if (/^(com|xyz|net|org|applejr)\./i.test(code)) return "Perfil"
  if (lower.includes("dns")) return "DNS"
  if (lower.includes("vpn")) return "VPN"
  if (lower.includes("proxy")) return "Proxy"
  if (lower.includes("warp")) return "Warp"
  if (lower.includes("profile")) return "Profile"

  return "Código"
}

function findOperations(text) {
  let ops = []
  let regex = /(install|installed|remove|removed|removal)/gi
  let m

  while ((m = regex.exec(text)) !== null) {
    let raw = m[1].toLowerCase()

    ops.push({
      type: raw.includes("install") ? "Instalação" : "Remoção",
      index: m.index
    })
  }

  return ops
}

function nearestOperation(ops, index) {
  let best = null
  let bestDistance = Infinity

  for (let op of ops) {
    let d = Math.abs(op.index - index)

    if (d < bestDistance) {
      best = op
      bestDistance = d
    }
  }

  return best
}

function dateNear(text, index) {
  let block = text.slice(Math.max(0, index - 9000), Math.min(text.length, index + 9000))

  let patterns = [
    /\d{2}\/\d{2}\/\d{4}[, ]+\d{2}:\d{2}:\d{2}/,
    /\d{2}-\d{2}-\d{4}[, ]+\d{2}:\d{2}:\d{2}/,
    /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/,
    /\d{2}:\d{2}:\d{2}/
  ]

  for (let p of patterns) {
    let m = block.match(p)
    if (m) return m[0]
  }

  return "Data/hora interna do bplist"
}

function removeSubMatches(codes) {
  let sorted = codes.slice().sort((a, b) => b.code.length - a.code.length)
  let final = []

  for (let item of sorted) {
    let inside = final.some(big => big.code !== item.code && big.code.includes(item.code))
    if (!inside) final.push(item)
  }

  return final
}

function extractCodes(text) {
  let found = []

  let regexes = [
    /([a-zA-Z0-9._~\-]{12,260})/g
  ]

  const ignoreWords = [
    "ProfileEvents",
    "SystemSettings",
    "SystemClientRestrictions",
    "SystemProfileRestrictions",
    "EffectiveSettings",
    "Restrictions",
    "Timestamp",
    "Operation",
    "Process",
    "clientRestrictions",
    "clientType",
    "restrictedBool",
    "intersection",
    "union",
    "values",
    "event",
    "timestamp",
    "process",
    "install",
    "remove",
    "removed",
    "installed",
    "apple.com",
    "plist",
    "bplist",
    "ManagedConfiguration",
    "ManagedSettingsExtension",
    "MCRestrictionManagerWriter",
    "RecomputeEffectiveUserSettings",
    "applyRestrictionDictionary"
  ]

  const mustLookLike = [
    /^[a-f0-9]{32,128}$/i,
    /^[a-f0-9]{32,128}-[a-f0-9-]{20,80}$/i,
    /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i,
    /^(com|xyz|net|org|applejr)\./i,
    /dns/i,
    /vpn/i,
    /proxy/i,
    /warp/i,
    /profile/i,
    /adguard/i,
    /cloudflare/i,
    /fatality/i,
    /khoindvn/i,
    /khoivdon/i
  ]

  for (let regex of regexes) {
    let m

    while ((m = regex.exec(text)) !== null) {
      let code = cleanCode(m[1])
      let lower = code.toLowerCase()

      if (!code || code.length < 12) continue
      if (ignoreWords.some(w => lower.includes(w.toLowerCase()))) continue
      if (!mustLookLike.some(r => r.test(code))) continue

      found.push({
        code,
        index: m.index,
        codeType: classifyCode(code)
      })
    }
  }

  return removeSubMatches(found)
}

function uniqueEvents(events) {
  let map = {}

  for (let ev of events) {
    let key = `${ev.source}|${ev.action}|${ev.code}`
    if (!map[key]) map[key] = ev
  }

  return Object.values(map)
}

function extractEvents(text, path) {
  let source = getSource(path, text)
  let ops = findOperations(text)
  let codes = extractCodes(text)
  let events = []

  for (let c of codes) {
    let op = nearestOperation(ops, c.index)
    let action = op ? op.type : "Detectado"

    events.push({
      source,
      action,
      code: c.code,
      codeType: c.codeType,
      date: op ? dateNear(text, c.index) : "Sem install/remove próximo",
      file: path,
      proxyOwner: detectProxyOwner(c.code)
    })
  }

  return uniqueEvents(events)
}

function generateHtml(data) {
  let installed = data.events.filter(e => e.action === "Instalação")
  let removed = data.events.filter(e => e.action === "Remoção")
  let detected = data.events.filter(e => e.action === "Detectado")
  let proxyDetected = data.events.filter(e => e.proxyOwner)
  let mcSettingsEvents = data.events.filter(e => e.source === "MCSettingsEvents")
  let mcProfileEvents = data.events.filter(e => e.source === "MCProfileEvents")

  function card(ev) {
    let cls = ev.action === "Remoção" ? "remove" : ev.action === "Instalação" ? "install" : "event"

    return `
      <div class="card">
        <div class="card-main">
          <span class="tag ${cls}">${ev.action}</span>
          <span class="source">${ev.source}</span>
          <span class="type">${ev.codeType}</span>
          <div class="code">${ev.code}</div>
          ${ev.proxyOwner ? `<div class="proxy-alert">⚠ Proxy ${ev.proxyOwner} detectado</div>` : ""}
          <div class="file">${ev.file.split("/").pop()}</div>
        </div>
        <div class="date">${ev.date}</div>
      </div>
    `
  }

  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>${APP_NAME}</title>
<style>
body { background:#050505; color:#eee; font-family: Menlo, monospace; padding:22px; }
.header { text-align:center; margin-top:28px; margin-bottom:52px; padding:30px 0 20px 0; }
.main-name { color:#fff; font-size:108px; font-weight:900; letter-spacing:18px; text-shadow:0 0 18px #fff, 0 0 42px #fff, 0 0 80px #777; line-height:1; }
.credits { margin-top:26px; color:#bbb; font-size:34px; letter-spacing:5px; line-height:2; text-shadow:0 0 10px #555; }
.discord { color:#fff; font-size:36px; font-weight:800; text-shadow:0 0 12px #fff, 0 0 24px #777; }
.section { border:1px solid #222; padding:18px; margin:22px 0; background:#080808; }
.title { color:#888; letter-spacing:5px; margin-bottom:18px; }
.row { display:flex; justify-content:space-between; border-bottom:1px solid #111; padding:12px 0; }
.label { color:#888; }
.value { color:#fff; }
.card { border:1px solid #181818; padding:14px; margin:12px 0; background:#0b0b0b; display:flex; justify-content:space-between; gap:16px; }
.card-main { flex:1; min-width:0; }
.tag { padding:5px 10px; border-radius:4px; font-size:12px; }
.install { background:#063b1e; color:#6bff9e; }
.remove { background:#410610; color:#ff5c72; }
.event { background:#302406; color:#ffd56b; }
.source { color:#ffd56b; margin-left:8px; font-size:12px; }
.type { color:#777; margin-left:8px; font-size:12px; }
.code { margin-top:12px; color:#fff; font-size:16px; word-break:break-all; }
.file { margin-top:8px; color:#555; font-size:12px; }
.date { color:#aaa; white-space:nowrap; font-size:13px; text-align:right; }
.proxy-alert { margin-top:10px; color:#ff4f68; font-size:14px; font-weight:700; text-shadow:0 0 8px #600; }
</style>
</head>
<body>

<div class="header">
  <div class="main-name">${APP_NAME}</div>
  <div class="credits">CRÉDITOS: ${CREDIT}<br><span class="discord">${DISCORD}</span></div>
</div>

<div class="section">
  <div class="title">◆ ARQUIVOS ANALISADOS</div>
  <div class="row"><span class="label">Arquivos lidos</span><span class="value">${data.filesRead}</span></div>
  <div class="row"><span class="label">Eventos únicos</span><span class="value">${data.events.length}</span></div>
  <div class="row"><span class="label">MCSettingsEvents</span><span class="value">${mcSettingsEvents.length}</span></div>
  <div class="row"><span class="label">MCProfileEvents</span><span class="value">${mcProfileEvents.length}</span></div>
  <div class="row"><span class="label">Proxys detectados</span><span class="value">${proxyDetected.length}</span></div>
</div>

<div class="section"><div class="title">◆ AVISOS DE PROXY (${proxyDetected.length})</div>${proxyDetected.length ? proxyDetected.map(card).join("") : "<p>Nenhum proxy conhecido detectado.</p>"}</div>
<div class="section"><div class="title">◆ PERFIS INSTALADOS (${installed.length})</div>${installed.length ? installed.map(card).join("") : "<p>Nenhuma instalação encontrada.</p>"}</div>
<div class="section"><div class="title">◆ PERFIS REMOVIDOS (${removed.length})</div>${removed.length ? removed.map(card).join("") : "<p>Nenhuma remoção encontrada.</p>"}</div>
<div class="section"><div class="title">◆ MCSETTINGSEVENTS (${mcSettingsEvents.length})</div>${mcSettingsEvents.length ? mcSettingsEvents.map(card).join("") : "<p>Nenhum hash/perfil encontrado na MCSettingsEvents.</p>"}</div>
<div class="section"><div class="title">◆ MCPROFILEEVENTS (${mcProfileEvents.length})</div>${mcProfileEvents.length ? mcProfileEvents.map(card).join("") : "<p>Nenhum evento encontrado na MCProfileEvents.</p>"}</div>
<div class="section"><div class="title">◆ DETECTADOS SEM AÇÃO (${detected.length})</div>${detected.length ? detected.map(card).join("") : "<p>Nenhum detectado sem ação.</p>"}</div>

</body>
</html>
`
}

async function getInputPath() {
  await alertMsg("Hooking", "Selecione a pasta extraída da sysdiagnose e toque em Abrir.")
  return await DocumentPicker.openFolder()
}

async function main() {
  let fm = FileManager.local()
  let input = await getInputPath()
  let files = fm.isDirectory(input) ? walkDirectory(fm, input) : [input]

  let allEvents = []
  let filesRead = 0

  for (let file of files) {
    let raw = readFileText(fm, file)
    if (!raw) continue

    let text = normalizeText(raw)
    filesRead++

    allEvents.push(...extractEvents(text, file))
  }

  let cleanEvents = uniqueEvents(allEvents)

  cleanEvents.sort((a, b) => {
    if (a.proxyOwner && !b.proxyOwner) return -1
    if (!a.proxyOwner && b.proxyOwner) return 1
    if (a.source === "MCSettingsEvents" && b.source !== "MCSettingsEvents") return -1
    if (a.source !== "MCSettingsEvents" && b.source === "MCSettingsEvents") return 1
    if (a.action === "Instalação" && b.action !== "Instalação") return -1
    if (a.action === "Remoção" && b.action !== "Remoção") return 1
    return a.code.localeCompare(b.code)
  })

  let html = generateHtml({
    events: cleanEvents,
    filesRead
  })

  let outFM = FileManager.iCloud()
  let dir = outFM.documentsDirectory()
  let path = outFM.joinPath(dir, `hooking_result_${Date.now()}.html`)

  outFM.writeString(path, html)

  await alertMsg(
    "Hooking finalizado",
    `Arquivos lidos: ${filesRead}\nEventos únicos: ${cleanEvents.length}`
  )

  QuickLook.present(path)
}

await main()
