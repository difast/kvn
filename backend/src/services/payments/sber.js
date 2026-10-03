// Skeleton for Sber Acquiring. Intentionally not implemented in the MVP.
//
// To connect it:
//  1. createPayment(): register the order at `${config.payments.sber.baseUrl}/register.do`
//     (amount = payment.amount_kop, orderNumber = payment.id, returnUrl = frontend /dashboard),
//     return { providerPaymentId: <orderId>, status: 'pending', redirectUrl: <formUrl> }.
//  2. parseWebhook(): verify the callback checksum with config.payments.sber.webhookSecret
//     and return { providerPaymentId, status: 'succeeded' | 'failed' }.
//  Everything else (subscription activation, VPN profile) is provider-agnostic and lives in
//  services/payments/index.js -> settle().
export function createSberProvider(config) {
  return {
    name: 'sber',
    async createPayment() {
      throw new Error('Sber acquiring is not implemented yet');
    },
    async parseWebhook() {
      throw new Error('Sber acquiring is not implemented yet');
    },
    config,
  };
}
