import { initScanner, captureFingerprint, disconnectScanner } from '../sdk/index'

async function main() {
  try {
    console.log('Detecting fingerprint scanner via WBF...')
    const device = await initScanner('wbf')
    console.log(`Vendor:   ${device.vendor}`)
    console.log(`Model:    ${device.model}`)
    console.log(`Serial:   ${device.serial}`)
    console.log(`Firmware: ${device.firmware}`)
    console.log(`Image:    ${device.imageWidth}x${device.imageHeight} @ ${device.dpi} DPI`)

    console.log('\n>>> Place your finger on the scanner <<<')
    const scan = await captureFingerprint({ timeoutMs: 30000, minQuality: 0 })
    console.log(`\nCapture OK!`)
    console.log(`  Quality:       ${scan.quality}`)
    console.log(`  Template size: ${scan.template.length}`)

    await disconnectScanner()
    console.log('\nDone!')
  } catch (err: any) {
    console.error('Error:', err.message)
    try { await disconnectScanner() } catch {}
    process.exit(1)
  }
}

main()
