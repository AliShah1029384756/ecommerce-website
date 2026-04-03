# ECommerce Website

![Course](https://img.shields.io/badge/Course-Web%20Development-0ea5e9)
![Stack](https://img.shields.io/badge/Stack-Node.js%20Express%20MongoDB-16a34a)

A full-stack coursework implementation of an e-commerce platform with static storefront pages and backend services for authentication and account recovery.

## Problem Statement

Build an online shopping workflow that combines user-facing storefront pages with a backend capable of handling authentication, password reset, and core route handling.

## Solution Overview

The project uses a Node.js and Express backend with MongoDB integration, paired with a multi-page frontend for catalog browsing, cart flow, and checkout journey.

## Features

- Multi-page storefront experience (`index`, `shop`, `cart`, `checkout`)
- Authentication flow (sign up, sign in, forgot password, reset password)
- Backend API routing via Express server
- Environment-based configuration for secure local setup

## Tech Stack

- Backend: Node.js, Express
- Database: MongoDB with Mongoose
- Frontend: HTML, CSS, JavaScript

## Setup

```bash
npm install
```

Create `.env` from `.env.example` and set required values.

## Usage

```bash
npm start
```

Default backend port: `3001` (override with `PORT`).

## Project Structure

```text
ECommerce Website/
|- Server.js
|- package.json
|- .env.example
|- index.html
|- shop.html
|- cart.html
|- checkout.html
|- signin.html
|- signup.html
|- forgot.html
|- reset-password.html
|- css/
|- js/
|- images/
```

## Limitations

- Coursework scope focuses on core workflow over production-grade hardening.
- Payment and deployment integrations are intentionally simplified.

## Future Improvements

- Add role-based admin panel for product management.
- Add order tracking and invoice export.
- Add automated tests for auth and cart routes.

## License

Currently portfolio and coursework use. Add an explicit LICENSE file for open reuse.

## Contact

- Maintainer: Syed Muhammad Ali Naqvi
- GitHub: https://github.com/AliShah1029384756
- LinkedIn: https://linkedin.com/in/ali-naqvi-1a9576331
