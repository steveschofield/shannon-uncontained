# Architecture Documentation

> Inferred architecture for http://192.168.1.130:3000

## Components

### api_v1

- **Type**: graphql
- **Description**: GraphQL API v1
- **Endpoints**: /api/v1

### api_v2

- **Type**: graphql
- **Description**: GraphQL API v2
- **Endpoints**: /api/v2

### rest_api

- **Type**: rest
- **Description**: REST API
- **Endpoints**: /rest

## Authentication

*No authentication flows identified*

## Workflows

### Checkout Workflow

1. Add to Cart → `/api/v1/cart/add`
1. View Cart → `/api/v1/cart/view`
1. Proceed to Checkout → `/api/v1/checkout/initiate`
1. Enter Payment Details → `/api/v1/checkout/payment`
1. Confirm Order → `/api/v1/checkout/confirm`

### Registration Workflow

1. Submit Registration Form → `/api/v2/register`
1. Verify Email Address → `/api/v2/verify/email`
1. Set Password → `/api/v2/set/password`

### Booking Workflow

1. Search for Flights → `/api/v1/flights/search`
1. Book Flight → `/api/v1/flights/book`

