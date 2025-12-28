
This is a helper script for logging in to AWS CLI/SDK with an MFA profile or using role-chaining

* This will prompt once per cache lifetime; subsequent CLI calls reuse cached JSON until it expires (refreshing 60 seconds early by default).
* If you need different final roles (admin vs readonly) but share the same jump role, define multiple credential_process profiles differing only in the final --role list.
* For non-interactive contexts (no TTY), MFA prompting will fail unless you pass --mfa-code (not recommended for automation).

### Install

```
git clone https://github.com/jyennaco/cloud-help.git
cd cloud-help
sudo cp aws/aws_credproc_chain.py /usr/local/bin/
sudo chmod 755 /usr/local/bin/aws_credproc_chain.py

# Create the python venv in order to install boto3 AWS Python SDK
python3 -m venv ~/venv
source ~/venv/bin/activate
python3 -m pip install aws/requirements.txt
```

### Configuration

* Sample AWS credentials file for the base long-running credentials

```
[baseProfile]
aws_access_key = ACCESS_KEY_ID
aws_secret_access_key = SECRET_ACCESS_KEY
```


* Sample AWS config file

```
[baseProfile]
region = us-east-2
output = text

# Example aame-account MFA login
[profile baseProfile-mfa]
region = us-east-2
credential_process = python3 /usr/local/bin/aws_credproc_chain.py --source-profile baseProfile --mfa-serial arn:aws:iam::111111111111:mfa/deviceName

# Exampling chaining through 2 roles in order
[profile baseProfile-chain]
credential_process = python3 /usr/local/bin/aws_credproc_chain.py --source-profile baseProfile --mfa-serial arn:aws:iam::111111111111:mfa/deviceName --session-duration 43200 --role arn:aws:iam::222222222222:role/JumpRole --role arn:aws:iam::333333333333:role/FinalAdminRole --role-duration 3600 --region us-east-1
region = us-east-1

```

### Usage

Run aws cli command or SDK calls as usual, specifying the desired profile based on the config files above. If the token is expiring within 60 seconds or expired, you will need to refresh your token and enter the MFA code when asked.

* Sample AWS CLI command using `-profile`

```
aws s3 ls --profile baseProfile-mfa
```

* Sample AWS CLI command using AWS_PROFILE environment variable

```
export AWS_PROFILE=baseProfile-chain
aws s3 ls
```

