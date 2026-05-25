import { initScanner, disconnectScanner } from '../sdk/index'

async function main() {
  try {
    console.log('Detecting scanner via WBF...')
    const device = await initScanner('wbf')
    console.log(`Detected: ${device.vendor} ${device.model}`)
    console.log('Scanner init OK! Your device works with WBF.')
    console.log('')
    console.log('Now attempting capture (WinBioIdentify)...')
    console.log('>>> Place your ENROLLED finger on the scanner <<<')

    // Import capture separately to add timeout wrapper
    const { captureFingerprint } = await import('../sdk/index')

    // Race against a manual timeout
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Manual timeout after 20s - sensor may not have detected finger')), 20000)
    )

    const scan = await Promise.race([
      captureFingerprint({ timeoutMs: 20000, minQuality: 0 }),
      timeout
    ])

    console.log(`\nCapture OK!`)
    console.log(`  Quality:       ${scan.quality}`)
    console.log(`  Template size: ${scan.template.length} bytes`)

    await disconnectScanner()
    console.log('Done!')
  } catch (err: any) {
    console.error('Error:', err.message)
    try { await disconnectScanner() } catch {}
    process.exit(1)
  }
}

main()
