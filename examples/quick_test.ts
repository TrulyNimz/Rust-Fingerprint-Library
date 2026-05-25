import {
  initScanner,
  captureFingerprint,
  disconnectScanner,
} from '../sdk/index'

async function main() {
  try {
    console.log('Initializing scanner...')
    const device = await initScanner('secugen')
    console.log(`Connected: ${device.vendor} ${device.model} (${device.serial.trim()})`)
    console.log(`Resolution: ${device.imageWidth}x${device.imageHeight} @ ${device.dpi} DPI`)

    console.log('\n>>> Place your finger on the scanner (30s timeout) <<<')
    const scan = await captureFingerprint({ timeoutMs: 30000, minQuality: 50 })
    console.log(`\nCapture OK!`)
    console.log(`  Quality:       ${scan.quality}`)
    console.log(`  Image bytes:   ${scan.image.length}`)
    console.log(`  Template size: ${scan.template.length}`)

    await disconnectScanner()
    console.log('\nDisconnected. Test passed!')
  } catch (err: any) {
    console.error('Error:', err.message)
    try { await disconnectScanner() } catch {}
    process.exit(1)
  }
}

main()
