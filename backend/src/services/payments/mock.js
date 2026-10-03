// Fake provider: every payment succeeds immediately. DEV/TEST ONLY.
export const mockProvider = {
  name: 'mock',
  // Returns { providerPaymentId, status, redirectUrl? }. Real providers return
  // status 'pending' + redirectUrl (hosted payment page) and confirm later via webhook.
  async createPayment(payment) {
    return { providerPaymentId: `mock_${payment.id}_${Date.now()}`, status: 'succeeded', redirectUrl: null };
  },
  // Real providers verify the signature and map the body to { providerPaymentId, status }.
  async parseWebhook() {
    throw new Error('mock provider has no webhooks');
  },
};
