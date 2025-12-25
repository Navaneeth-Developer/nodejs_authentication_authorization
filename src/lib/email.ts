import nodemailer from "nodemailer";

export async function sendEmail(to: string, subject: string, html: string) {
  if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_PORT ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASS
  ) {
    throw new Error("SMTP configuration is missing in environment variables.");
  }

  const Host = process.env.SMTP_HOST;
  const Port = parseInt(process.env.SMTP_PORT, 587);
  const User = process.env.SMTP_USER;
  const Pass = process.env.SMTP_PASS;
  const From = process.env.SMTP_FROM || User;

  const transporter = nodemailer.createTransport({
    host: Host,
    port: Port,
    secure: false,
    auth: {
      user: User,
      pass: Pass,
    },
  });
  const info = await transporter.sendMail({
    from: From,
    to,
    subject,
    html,
  });
}
