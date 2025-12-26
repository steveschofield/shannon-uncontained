# Architecture Documentation

> Inferred architecture for http://192.168.1.130:3000

## Components

### GraphQL API

- **Type**: graphql
- **Description**: GraphQL API endpoint
- **Endpoints**: http://192.168.1.130:3000/graphql

### REST API

- **Type**: rest
- **Description**: REST API endpoints
- **Endpoints**: http://192.168.1.130:3000/api, http://192.168.1.130:3000/api/v1, http://192.168.1.130:3000/api/v2

### Web Server

- **Type**: web_server
- **Description**: Web server endpoints
- **Endpoints**: http://192.168.1.130:3000/, http://192.168.1.130:3000/robots.txt

## Authentication

*No authentication flows identified*

## Workflows

### Checkout

1. Add to cart → `/api/v1/cart/add`
1. View cart → `/api/v2/cart/view`
1. Proceed to checkout → `/api/v1/checkout/initiate`
1. Enter payment details → `/api/v2/checkout/payment`
1. Confirm order → `/api/v1/checkout/confirm`

### Registration

1. Create account → `/api/v2/account/create`
1. Verify email → `/api/v1/account/verify-email`
1. Set password → `/api/v2/account/set-password`

### Booking

1. Search availability → `/api/v1/booking/search`
1. Book room → `/api/v2/booking/initiate`
1. Confirm booking → `/api/v1/booking/confirm`

