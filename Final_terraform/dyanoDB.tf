resource "aws_dynamodb_table" "api_log" {
  name           = "APILog1"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "timestamp"
  range_key      = "username"

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "username"
    type = "S"
  }
}
