# logs.tf

# Set up CloudWatch group and log stream and retain logs for 30 days
resource "aws_cloudwatch_log_group" "smuggler_log_group" {
  name              = "/ecs/smuggler-app"
  retention_in_days = 30

  tags = {
    Name = "smuggler-log-group"
  }
}

resource "aws_cloudwatch_log_stream" "smuggler_log_stream" {
  name           = "smuggler-log-stream"
  log_group_name = aws_cloudwatch_log_group.smuggler_log_group.name
}

