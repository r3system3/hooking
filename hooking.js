// HOOKING - Versão Melhorada para MCSettingsEvents

const APP_NAME = "HOOKING"
const CREDIT = "SANTOS e r3"
const DISCORD = "discord.gg/hooking"

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
  await alertMsg("Hooking", "Selecione o MCProfileEvents.plist (se tiver)")
  let profile = await DocumentPicker.openFile()
  return [settings, profile]
}

function readAny(fm, path) {
  let out = ""
  try { out += fm.readString(path) || "" } catch(e){}
  try {
    let data = fm.read(path)
    if (data) out += "\n" + data.toRawString()
  } catch(e){}
  return out
}

function cleanRaw(raw) {
  return String(raw || "")
    .replace(/\0/g, " ")
    .replace(/[\x00-\x1F\x7F]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
}

function extractInterestingItems(text) {
  let items = []

  // Pega bundle IDs e processos
  const bundleRegex = /([a-zA-Z0-9_.-]+\.[a-zA-Z0-9_.-]{8,})/g
  let match
  while ((match = bundleRegex.exec(text)) !== null) {
    let code = match[1]
    if (code.length > 15 && !code.includes("apple") && !code.includes("MCRestrictionManagerWriter")) {
      items.push({
        code: code,
        type: "Bundle / Processo",
        date: extractDateNear(text, match.index)
      })
    }
  }

  // Pega datas importantes
  const dateRegex = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/g
  while ((match = dateRegex.exec(text)) !== null) {
    items.push({
      code: match[0],
      type: "Timestamp",
      date: match[0]
    })
  }

  // Pega chaves de restrições relevantes
  const restrictionRegex = /allow[A-Z][a-zA-Z0-9]+|force[A-Z][a-zA-Z0-9]+|blacklistedAppBundleIDs|blockedAppBundleIDs/g
  while ((match = restrictionRegex.exec(text)) !== null) {
    items.push({
      code: match[0],
      type: "Restrição",
      date: extractDateNear(text, match.index)
    })
  }

  return items
}

function extractDateNear(text, index) {
  const block = text.slice(Math.max(0, index - 300), Math.min(text.length, index + 300))
  const dateMatch = block.match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)
  return dateMatch ? dateMatch[0] : "Sem data"
}

function generateHtml(events) {
  let html = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>${APP_NAME} - Relatório</title>
<style>
body { background:#0a0a0a; color:#ddd; font-family: Menlo, monospace; padding:20px; }
h1 { color:#fff; text-align:center; }
.card { background:#1a1a1a; border:1px solid #333; padding:12px; margin:10px 0; border-radius:6px; }
.type { color:#6cf; font-size:13px; }
.code { word-break:break-all; margin:6px 0; font-size:15px; color:#fff; }
.date { color:#aaa; font-size:13px; }
</style>
</head>
<body>
<h1>${APP_NAME} - Análise MCSettingsEvents</h1>
<p>Eventos encontrados: ${events.length}</p>
`

  events.forEach(ev => {
    html += `
<div class="card">
  <span class="type">${ev.type}</span><br>
  <div class="code">${ev.code}</div>
  <div class="date">${ev.date}</div>
</div>`
  })

  html += `</body></html>`
  return html
}

async function main() {
  let fm = FileManager.local()
  let files = await pickMCFiles()
  let allEvents = []

  for (let file of files) {
    let raw = readAny(fm, file)
    if (raw.length < 100) continue

    let text = cleanRaw(raw)
    allEvents.push(...extractInterestingItems(text))
  }

  let html = generateHtml(allEvents)

  let outFM = FileManager.iCloud()
  let path = outFM.joinPath(outFM.documentsDirectory(), `hooking_result_${Date.now()}.html`)
  outFM.writeString(path, html)

  await alertMsg("Pronto", `Foram encontrados ${allEvents.length} itens`)
  QuickLook.present(path)
}

await main()
