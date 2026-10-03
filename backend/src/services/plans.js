// Prices are integers in kopecks to avoid float errors.
export const PLANS = {
  monthly: { id: 'monthly', title: 'VPN на 30 дней', priceKop: 50000, currency: 'RUB', days: 30 },
};
export const DEFAULT_PLAN_ID = 'monthly';
