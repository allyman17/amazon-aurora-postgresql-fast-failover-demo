import boto3
import cfnresponse
import time
from botocore.exceptions import ClientError

def handler(event, context):
    acm = boto3.client('acm', region_name='us-east-1')
    physical_id = 'AcmCertCreator'

    try:
        if event['RequestType'] in ['Create', 'Update']:
            domain_name = event['ResourceProperties']['DomainName']
            validation_domain = event['ResourceProperties']['ValidationDomain']
            
            response = acm.request_certificate(
                DomainName=domain_name,
                ValidationMethod='DNS',
                SubjectAlternativeNames=[domain_name],
                IdempotencyToken=context.aws_request_id,
                DomainValidationOptions=[{
                    'DomainName': domain_name,
                    'ValidationDomain': validation_domain
                }]
            )
            
            cert_arn = response['CertificateArn']
            
            # Wait for DNS validation to be ready
            waiter = acm.get_waiter('certificate_validated')
            waiter.wait(
                CertificateArn=cert_arn,
                WaiterConfig={'MaxAttempts': 20, 'Delay': 30}
            )
            
            cfnresponse.send(event, context, cfnresponse.SUCCESS, 
                           {'CertificateArn': cert_arn}, physical_id)

        elif event['RequestType'] == 'Delete':
            cert_arn = event['PhysicalResourceId']
            try:
                acm.delete_certificate(CertificateArn=cert_arn)
            except acm.exceptions.ResourceNotFoundException:
                pass
            cfnresponse.send(event, context, cfnresponse.SUCCESS, 
                           {}, physical_id)

    except ClientError as e:
        error_msg = f"ACM Error: {str(e)}"
        cfnresponse.send(event, context, cfnresponse.FAILED, 
                       {'Error': error_msg}, physical_id)
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        cfnresponse.send(event, context, cfnresponse.FAILED,
                       {'Error': error_msg}, physical_id)
