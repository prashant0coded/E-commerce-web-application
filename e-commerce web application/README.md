# E-Commerce Store: Express + MongoDB

Features: product catalog with search and category filter, cart (kept in the browser), checkout, order tracking,
JWT login, and Admin/User roles.

## Run locally
1. `npm install`
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, `JWT_SECRET`, and `ADMIN_EMAIL`.
3. `npm run dev`, open http://localhost:3000.
4. Register using the exact `ADMIN_EMAIL` address to become the admin. Everyone else registers as a normal user.

## Roles
| Action | Guest | User | Admin |
|---|---|---|---|
| Browse products | yes | yes | yes |
| Place / view / cancel own orders | no | yes | yes |
| Add, edit, delete products | no | no | yes |
| View all orders, change order status | no | no | yes |

## API
| Method | Route | Access |
|---|---|---|
| POST | /api/auth/register, /api/auth/login | public |
| GET | /api/products?search=&category= | public |
| POST / PUT / DELETE | /api/products(/:id) | admin |
| POST | /api/orders | user |
| GET | /api/orders (admin: `?all=1`) | user / admin |
| PUT | /api/orders/:id/cancel | owner, pending only |
| PUT | /api/orders/:id/status | admin |

Design notes: prices are stored as integer cents; the server recalculates every total from the database (never trusts the
browser); stock is reserved atomically at checkout and returned if the order fails or is cancelled.

## Deploy
Render or Railway (build `npm install`, start `npm start`) with the three env vars. Add a MongoDB Atlas cluster and
allow access from anywhere (0.0.0.0/0).

## Next steps
Real payments (Stripe Checkout), email receipts, product image uploads, pagination.
