resource "aws_s3_bucket" "data" {
  bucket = "testbed-data"
  acl    = "public-read"
}
resource "aws_security_group" "open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  engine              = "mysql"
  password            = "admin123"
  storage_encrypted   = false
  publicly_accessible = true
}
