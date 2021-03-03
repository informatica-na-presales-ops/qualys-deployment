# qualys-deployment

This tool will attempt to install the Qualys Cloud Agent on running EC2 instances in AWS.

## Usage

You will need the following things to successfully run this tool:

* The **Access Key ID** and **Secret Access Key** to connect to your AWS account
* The Qualys **Activation ID** and **Customer ID** to activate the Qualys Cloud Agent on your AWS EC2 instances
* A directory with **SSH private keys** that will be used to make SSH connections to your instances
* A directory with the Qualys Cloud Agent installation packages `QualysCloudAgent.deb` and `QualysCloudAgent.rpm`,
  depending on which Linux distributions you are deploying the agent to (if you only have Amazon Linux instances, you
  only need the `.rpm` package; if you only have Ubuntu instances, you only need the `.deb` package)

The following environment variables are required:

* `AWS_ACCESS_KEY_ID`
* `AWS_SECRET_ACCESS_KEY`
* `QUALYS_ACTIVATION_ID`
* `QUALYS_CUSTOMER_ID`

The following environment variables have defaults, but you may need to set them for you environment:

* `KEYFILE_LOCATION`  
  the directory where your private key files are stored  
  default: `/keys`
* `QUALYS_DEB`  
  the full path to `QualysCloudAgent.deb`  
  default: `/packages/QualysCloudAgent.deb`
* `QUALYS_RPM`  
  the full path to `QualysCloudAgent.rpm`  
  default: `/packages/QualysCloudAgent.rpm`

By default, when you launch the tool it will process all currently running EC2 instances in your account, then pause and
repeat every 23 hours. The following environment variables control this behavior:

* `RUN_AND_EXIT`  
  set to `true` if you want the tool to quit immediately after processing all running instances  
  default: `false`
* `RUN_INTERVAL`  
  set to the number of minutes to wait between repeated runs  
  default: `1380` (23 hours)

If you only want to install the agent on a single instance, identify the instance as a command-line argument to the tool
in the format `region/instance-id`. For example:

```shell
python deploy-to-aws.py us-east-1/i-0123456789abcdef0
```

### Choosing an SSH user and keyfile

This tool will follow these steps to determine the username to use for the SSH connection:

1. Check the instance for a tag named `machine__ssh_user` and use the value of this tag if it exists
2. Use `ec2-user`

This tool will follow these steps to determine the keyfile to use for the SSH connection:

1. Check the instance for a tag named `machine__ssh_keyfile` and use the value of this tag if it exists
2. Check the instance for the `key_name` attribute (the name of the key pair used to launch the instance), and use the
   value if it exists

The files in the folder specified by the environment variable `KEYFILE_LOCATION` should match the above values exactly.

After the tool determines the username and keyfile to use for the connection it attempts to establish a connection to
the instance's public IP address.

## Excluding an instance

If you want to exclude an instance from having the agent installed by this tool, set a tag on the instance named
`machine__install_qualys` to `false`.
