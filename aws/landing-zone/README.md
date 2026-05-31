# AWS Landing Zone

Baseline AWS Control Tower configuration and account vending.

## Structure

- `control-tower/` -- AFT (Account Factory for Terraform) baseline
- `account-baseline/` -- Applied to every new account on vending

## Deployment Order

1. Enable AWS Organizations
2. Enable Control Tower in management account
3. Deploy AFT pipeline
4. Vend member accounts via `account-baseline/`
