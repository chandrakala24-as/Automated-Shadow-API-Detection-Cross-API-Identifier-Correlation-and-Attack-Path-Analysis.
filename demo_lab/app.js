// RideShop front-end client. Internal routes are referenced here, as in many real bundles.
const api = {
  me: () => fetch("/api/v1/me"),
  posts: () => fetch("/api/v1/posts"),
  products: () => fetch("/api/v1/products"),
  profile: (userId) => fetch(`/api/internal/users/${userId}`),
  resetPassword: (userId) =>
    fetch(`/api/internal/users/${userId}/reset-password`, { method: "POST" }),
  vehicle: (vehicleId) => fetch(`/api/v1/vehicles/${vehicleId}/location`),
  adminUsers: () => fetch("/api/internal/admin/users"),
  oldOrder: (orderId) => fetch("/api/v0/orders/" + orderId),
};
window.rideShop = api;
