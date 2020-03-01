# ssh-me-in

`ssh-me-in` is a command line utility to add rules to one or more AWS EC2 security groups which allow you to SSH in. This can be useful for remote workers with a dynamic IP address who regularly need to SSH into EC2 instances.

## Configuration

By default `ssh-me-in` will use authenticate using AWS CLI credentials and the region specified in the`AWS_DEFAULT_REGION` or `AWS_REGION` environment variable if set. If the region is not specified in one of those environment variables it will fall back to the region in your config. Additionally, the region can be specified (overriding all other sources of config) via the command line `region` argument.

To specify the security groups to add your IP address to you must provide a file with a security group id on each line. The default location this file is expected to be at is `$HOME/.ssh-me-in`, but an alternative config location can be specified using the `--config` option.

### Example config file

```
sg-d9e3fgad
sg-b02184cc
```
