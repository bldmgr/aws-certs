# aws-certs



# Basic import
./aws-certs -cert cert.pem -key privkey.pem -region us-east-1 -tags 'Environment=qa,Application=web'

# With certificate chain and tags
./aws-certs -cert cert.pem -key key.pem -chain chain.pem -tags 'Environment=prod,Application=web'

# Specify region and profile
./aws-certs -cert cert.pem -key key.pem -region us-west-2 -profile myprofile