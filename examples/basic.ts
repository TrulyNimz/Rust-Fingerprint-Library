import {
  initScanner,
  captureFingerprint,
  enrollUser,
  verifyUser,
  identifyUser,
  disconnectScanner,
  getScannerStatus,
} from '../sdk/index'
import type { Template } from '../sdk/index'

async function main() {
  try {
    // Check status before init
    const statusBefore = await getScannerStatus()
    console.log('Status:', statusBefore.status)

    // 1. Initialize the scanner (spawns 32-bit bridge process)
    console.log('\n--- Initializing Scanner ---')
    const device = await initScanner('secugen')
    console.log(`Vendor:   ${device.vendor}`)
    console.log(`Model:    ${device.model}`)
    console.log(`Serial:   ${device.serial}`)
    console.log(`DPI:      ${device.dpi}`)
    console.log(`Image:    ${device.imageWidth}x${device.imageHeight}`)

    // 2. Capture a single fingerprint
    console.log('\n--- Capturing Fingerprint ---')
    console.log('Place your finger on the scanner...')
    const scan = await captureFingerprint({
      timeoutMs: 15000,
      minQuality: 70,
    })
    console.log(`Quality:       ${scan.quality}`)
    console.log(`Image bytes:   ${scan.image.length}`)
    console.log(`Template size: ${scan.template.length}`)

    // 3. Enroll a user (3 samples)
    console.log('\n--- Enrolling User ---')
    console.log('Place your finger 3 times when prompted...')
    const template = await enrollUser('user-001', 3)
    console.log(`Enrolled user: ${template.userId}`)
    console.log(`Template size: ${template.data.length} bytes`)

    // 4. Verify the user (1:1)
    console.log('\n--- Verifying User ---')
    console.log('Place your finger to verify...')
    const verifyResult = await verifyUser('user-001', template)
    console.log(`Matched: ${verifyResult.matched}`)
    console.log(`Score:   ${verifyResult.score}`)

    // 5. Identify against a list (1:N)
    console.log('\n--- Identifying User ---')
    console.log('Place your finger to identify...')
    const templates: Template[] = [template]
    const identifyResult = await identifyUser(templates)
    console.log(`Matched:  ${identifyResult.matched}`)
    console.log(`User ID:  ${identifyResult.userId ?? 'none'}`)
    console.log(`Score:    ${identifyResult.score}`)

    // 6. Disconnect (kills bridge process)
    console.log('\n--- Disconnecting ---')
    await disconnectScanner()

    const statusAfter = await getScannerStatus()
    console.log('Status:', statusAfter.status)

    console.log('\nDone!')
  } catch (err: any) {
    console.error('Error:', err.message)
    try {
      await disconnectScanner()
    } catch {}
    process.exit(1)
  }
}

main()
