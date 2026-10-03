// Mail transport placeholder. Replace with SMTP / transactional-mail provider later.
export const consoleMailer = {
  async send({ to, subject, text }) {
    console.log(`[mail] to=${to} subject=${subject}\n${text}`);
  },
};
