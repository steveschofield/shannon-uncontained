# Architecture Documentation

> Inferred architecture for http://192.168.1.130:3000

## Components

### GraphQL Service

- **Type**: graphql
- **Description**: Handles GraphQL queries and mutations
- **Endpoints**: http://192.168.1.130:3000/graphql

### REST Service

- **Type**: rest
- **Description**: Handles RESTful API requests
- **Endpoints**: http://192.168.1.130:3000/rest

## Authentication

*No authentication flows identified*

## Workflows

### Checkout Workflow

1. Add to Cart → `/api/v1/cart/add`
1. View Cart → `/api/v1/cart/view`
1. Proceed to Checkout → `/api/v1/checkout/initiate`
1. Enter Shipping Details → `/api/v1/checkout/shipping`
1. Confirm Order → `/api/v1/checkout/confirm`

### Registration Workflow

1. Create Account → `/api/v2/account/create`
1. Verify Email → `/api/v2/account/verify-email`
1. Set Password → `/api/v2/account/set-password`

### Booking Workflow

1. Search for Flights → `/api/v1/flights/search`
1. Book Flight → `/api/v1/flights/book`

