// HOOKING - Versão Ultra Agressiva na Detecção

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
  await alertMsg("Hooking", "Selecione o MCSettingsEvents.plist")
  let settings = await DocumentPicker.openFile()
  await alertMsg("Hooking", "Selecione o MCProfileEvents.plist")
  let profile = await DocumentPicker.openFile()
  return [settings, profile]
}

// Leitura ULTRA agressiva
function readAny(fm, path) {
  let out = ""
  try {
    out += (fm.readString(path) || "")
  } catch(e) {}

  try {
    let data = fm.read(path)
    if (data) {
      out += "\n" + data.toRawString()
      // Força conversão de bytes
      let bytes = []
      for (let i = 0; i < Math.min(data.length, 500000); i++) {
        bytes.push(data[i])
      }
      out += "\n" + String.fromCharCode.apply(null, bytes)
    }
  } catch(e) {}

  return out
}

function cleanRaw(raw) {
  return String(raw || "")
    .replace(/\0/g, " ")
    .replace(/[\x00-\x1F\x7F-\x9F]/g, " ")
    .replace(/[^ -~À-ÿa-f0-9]/gi, " ")
    .replace(/\s+/g, " ")
    .trim()
}

function getSource(path) {
  let p = path.toLowerCase()
  return p.includes("setting") ? "MCSettingsEvents" : "MCProfileEvents"
}

// Detecção agressiva
function cleanCode(code) {
  return String(code).trim().replace(/^[^a-zA-Z0-9]+/, "").replace(/[^a-zA-Z0-9._~\-]+$/, "").trim()
}

function looksLikeCode(code) {
  if (!code || code.length < 20) return false
  let l = code.toLowerCase()
  if (/^[a-f0-9]{40,120}$/i.test(code)) return true
  if (/^[a-f0-9]{32,}-[a-f0-9-]{20,80}$/i.test(code)) return true
  if (/^(com|net|org|xyz|io|me)\./i.test(code)) return true
  if (l.includes("proxy") || l.includes("vpn") || l.includes("dns")) return true
  return false
}

function classifyCode(code) {
  if (/^[a-f0-9]{40,}$/i.test(code)) return "Hash"
  if (/[a-f0-9-]{30,}/.test(code)) return "Hash+UUID"
  if (/^com\./i.test(code)) return "Perfil"
  return "Código"
}

function detectProxyOwner(code) {
  let l = String(code).toLowerCase()
  for (let rule of PROXY_RULES) {
    for (let p of rule.prefixes) {
      if (l.startsWith(p)) return rule.name
    }
  }
  return null
}

// Funções restantes (mantidas simples)
function extractCodes(text) {
  let found = []
  const regexes = [
    /([a-f0-9]{32,}-[a-f0-9-]{20,})/gi,
    /([a-f0-9]{40,120})/gi,
    /((?:com|net|org|xyz)\.[a-zA-Z0-9._-]{10,100})/gi
  ]

  for (let r of regexes) {
    let m
    while ((m = r.exec(text)) !== null) {
      let code = cleanCode(m[1])
      if (looksLikeCode(code)) {
        found.push({code, index: m.index, codeType: classifyCode(code)})
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

  codes.forEach(c => {
    events.push({
      source,
      action: "Detectado",
      code: c.code,
      codeType: c.codeType,
      date: "Detectado no arquivo",
      file: path,
      proxyOwner: detectProxyOwner(c.code)
    })
  })

  return events
}

function generateHtml(data) {
  // HTML simplificado para teste rápido
  let html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${APP_NAME}</title>
<style>body{background:#000;color:#0f0;font-family:Menlo;padding:20px;}</style></head>
<body>
<h1>${APP_NAME} - DETECÇÃO</h1>
<p>Arquivos lidos: ${data.filesRead} | Eventos: ${data.events.length}</p>
${data.events.map(ev => `
  <div style="background:#111;padding:10px;margin:8px 0;border-left:4px solid #0f0;">
    <b>${ev.action}</b> - ${ev.codeType}<br>
    <small>${ev.code}</small><br>
    ${ev.proxyOwner ? `<b style="color:red">PROXY: ${ev.proxyOwner}</b>` : ''}
  </div>`).join('')}
</body></html>`

  return html
}

async function main() {
  let fm = FileManager.local()
  let files = await pickMCFiles()
  let allEvents = []
  let filesRead = 0

  for (let file of files) {
    let raw = readAny(fm, file)
    if (raw.length > 100) {
      filesRead++
      allEvents = allEvents.concat(extractEvents(raw, file))
    }
  }

  let html = generateHtml({events: allEvents, filesRead})
  let outFM = FileManager.iCloud()
  let path = outFM.joinPath(outFM.documentsDirectory(), `hooking_${Date.now()}.html`)
  outFM.writeString(path, html)

  await alertMsg("Finalizado", `Eventos encontrados: ${allEvents.length}`)
  QuickLook.present(path)
}

await main()
