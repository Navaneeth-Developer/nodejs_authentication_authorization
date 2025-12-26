import qr from "qrcode";

const otpAuthUrl = process.argv[2];

if (!otpAuthUrl) {
  console.error("Usage: ts-node scripts/totp-qr.ts <otpauth-url>");
  process.exit(1);
}

const generateQRCode = async (url: string) => {
  try {
    const qrCodeDataURL = await qr.toFile("totp-qr.png", url);
    console.log("QR code generated and saved to totp-qr.png");
  } catch (error) {
    console.error("Error generating QR code:", error);
  }
};
generateQRCode(otpAuthUrl);
