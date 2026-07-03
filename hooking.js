// HOOKING - Leitor direto de MCSettingsEvents e MCProfileEvents (Versão Forte)

const APP_NAME = "HOOKING"
const CREDIT = "SANTOS e r3"
const DISCORD = "discord.gg/hooking"

const PROXY_RULES = [
  { name: "Zeex free/vip", prefixes: ["78f", "d14"] },
  { name: "Desconhecida", prefixes: ["84", "7d", "60a", "051", "3c4", "ae7", "0af", "proxyady", "704", "0d", "40e", "59ac"] },
  { name: "Fatality bypass", prefixes: ["1ea", "b0", "2c", "9d"] },
  { name: "Luxe cheats", prefixes: ["b9", "a4"] },
  { name: "XTREMO", prefixes: ["com.xtremo.mobile"] },
  { name: "Dash", prefixes: ["70a", "dash.proxy"] },
  { name: "brisado", prefixes: ["a4c"] }
]

async function alertMsg(title, message) {
  let a = new Alert()
  a.title = title
  a.message = message
  a.addAction("OK")
  await a.present()
}

async function pickMCFiles() {
  await alertMsg("Hooking", "Selecione primeiro o MCSettingsEvents.plist.")
  let settings = await DocumentPicker.openFile()
  await alertMsg("Hooking", "Agora selecione o MCProfileEvents.plist.")
  let profile = await DocumentPicker.openFile()
  return [settings, profile]
}

// Leitura mais agressiva possível
function readAny(fm, path) {
  let out = ""
  try {
    out += fm.readString(path) || ""
  } catch (e) {}
  try {
    let data = fm.read(path)
    if (data) {
      out += "\n" + data.toRawString()
    }
  } catch (e) {}
  return out
}

function cleanRaw(raw) {
  return String(raw || "")
    .replace(/\0/g, " ")
    .replace(/[\x00-\x1F\x7F]/g, " ")
    .replace(/[^ -~a-f0-9]/gi, " ")
    .replace(/\s+/g, " ")
    .trim()
}

function getSource(path) {
  let p = path.toLowerCase()
  return p.includes("setting") ? "MCSettingsEvents" : "MCProfileEvents"
}

function cleanCode(code) {
  return String(code || "").trim()
    .replace(/^[^a-zA-Z0-9]+/, "")
    .replace(/[^a-zA-Z0-9._~\-]+$/, "")
    .trim()
}

function looksLikeCode(code) {
  if (!code || code.length < 24) return false
  let lower = code.toLowerCase()
  if (/^[a-f0-9]{40,128}$/i.test(code)) return true
  if (/^[a-f0-9]{32,}-[a-f0-9-]{20,80}$/i.test(code)) return true
  if (/^(com|net|org|xyz|io|me)\.[a-z0-9._-]{8,}$/i.test(code)) return true
  if (lower.includes("proxy") || lower.includes("vpn") || lower.includes("dns")) return true
  return false
}

function classifyCode(code) {
  if (/^[a-f0-9]{40,}$/i.test(code)) return "Hash"
  if (/^[a-f0-9]{32,}-[a-f0-9-]{20,}$/i.test(code)) return "Hash + UUID"
  if (/^com\./i.test(code)) return "Perfil"
  return "Código"
}

function detectProxyOwner(code) {
  let lower = String(code).toLowerCase()
  for (let rule of PROXY_RULES) {
    for (let prefix of rule.prefixes) {
      if (lower.startsWith(prefix.toLowerCase())) return rule.name
    }
  }
  return null
}

function extractCodes(text) {
  let found = []
  const regexes = [
    /([a-f0-9]{32,}-[a-f0-9-]{20,})/gi,
    /([a-f0-9]{40,128})/gi,
    /((?:com|net|org|xyz|io|me)\.[a-zA-Z0-9._-]{10,140})/gi
  ]

  for (let regex of regexes) {
    let m
    while ((m = regex.exec(text)) !== null) {
      let code = cleanCode(m[1])
      if (looksLikeCode(code)) {
        found.push({
          code: code,
          index: m.index,
          codeType: classifyCode(code)
        })
      }
    }
  }
  return found
}

function extractEvents(raw, path) {
  let text = cleanRaw(raw)
  let source = getSource(path)
  let codes = extractCodes(text)
  let events = []

  for (let c of codes) {
    events.push({
      source: source,
      action: "Detectado",
      code: c.code,
      codeType: c.codeType,
      date: "Detectado",
      file: path,
      proxyOwner: detectProxyOwner(c.code)
    })
  }
  return events
}

function generateHtml(data) {
  let installed = data.events.filter(e => e.action.includes("Instal"))
  let removed = data.events.filter(e => e.action.includes("Remo"))
  let proxyDetected = data.events.filter(e => e.proxyOwner)

  function card(ev) {
    let cls = "event"
    return `
      <div class="card">
        <div class="card-main">
          <span class="tag ${cls}">${ev.action}</span>
          <span class="source">${ev.source}</span>
          <span class="type">${ev.codeType}</span>
          <div class="code">${ev.code}</div>
          ${ev.proxyOwner ? `<div class="proxy-alert">⚠ ${ev.proxyOwner}</div>` : ""}
        </div>
      </div>
    `
  }

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>${APP_NAME}</title>
<style>
body { background:#050505; color:#eee; font-family:Menlo,monospace; padding:20px; }
.main-name { font-size:90px; text-align:center; }
.card { background:#111; padding:12px; margin:10px 0; border-left:4px solid #0a0; }
.code { word-break:break-all; font-size:15px; }
.proxy-alert { color:#ff4444; font-weight:bold; }
</style>
</head>
<body>
<div class="main-name">${APP_NAME}</div>
<div class="section"><h2>Eventos Encontrados: ${data.events.length}</h2>${data.events.map(card).join("")}</div>
</body>
</html>`
}

async function main() {
  let fm = FileManager.local()
  let files = await pickMCFiles()
  let allEvents = []
  let filesRead = 0

  for (let file of files) {
    let raw = readAny(fm, file)
    if (raw.length > 200) {
      filesRead++
      allEvents = allEvents.concat(extractEvents(raw, file))
    }
  }

  let html = generateHtml({ events: allEvents, filesRead })

  let outFM = FileManager.iCloud()
  let path = outFM.joinPath(outFM.documentsDirectory(), `hooking_result_${Date.now()}.html`)
  outFM.writeString(path, html)

  await alertMsg("Finalizado", `Eventos encontrados: ${allEvents.length}`)
  QuickLook.present(path)
}

await main()
