resource "random_pet" "name" {
  length    = 2
  separator = "-"
}


resource "aws_kinesis_stream" "test_stream" {
  name             = "test-${random_pet.name.id}"
  shard_count      = 1
  retention_period = 48

  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
  ]

  tags = {
    Environment = "test"
  }
}
