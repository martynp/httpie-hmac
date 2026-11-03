import unittest

import requests

from httpie_hmac import HmacAuth


class AWSEndpointTests(unittest.TestCase):
    def sign(self, hostname, **settings):
        return requests.Request(
            'GET', 'https://' + hostname + '/file.txt',
            auth=HmacAuth('EXAMPLE', 'dummy-secret', 'aws4', settings),
        ).prepare()

    def assert_scope(self, request, region, service):
        credential = request.headers['Authorization'].split('Credential=')[1]
        scope = credential.split(',')[0].split('/')
        self.assertEqual(scope[2:], [region, service, 'aws4_request'])

    def test_ordinary_regional_endpoints(self):
        for host, service in [
            ('ec2.eu-west-2.amazonaws.com', 'ec2'),
            ('s3.eu-west-2.amazonaws.com', 's3'),
            ('my.bucket.s3.eu-west-2.amazonaws.com', 's3'),
            ('api-id.execute-api.eu-west-2.amazonaws.com', 'execute-api'),
        ]:
            with self.subTest(host=host):
                self.assert_scope(self.sign(host), 'eu-west-2', service)

    def test_opensearch_domain_endpoint(self):
        self.assert_scope(
            self.sign('search-example.eu-west-2.es.amazonaws.com'),
            'eu-west-2', 'es',
        )

    def test_govcloud_region(self):
        self.assert_scope(
            self.sign('s3.us-gov-west-1.amazonaws.com'), 'us-gov-west-1', 's3',
        )

    def test_s3_dualstack_endpoints(self):
        for prefix in ['', 'bucket.', 'my.bucket.']:
            with self.subTest(prefix=prefix):
                self.assert_scope(
                    self.sign(prefix + 's3.dualstack.eu-west-2.amazonaws.com'),
                    'eu-west-2', 's3',
                )

    def test_region_and_service_overrides_are_independent(self):
        host = 's3.eu-west-2.amazonaws.com'
        for settings, region, service in [
            ({'region': 'us-east-1'}, 'us-east-1', 's3'),
            ({'service': 'execute-api'}, 'eu-west-2', 'execute-api'),
            ({'region': 'us-east-1', 'service': 'execute-api'},
             'us-east-1', 'execute-api'),
        ]:
            with self.subTest(settings=settings):
                self.assert_scope(self.sign(host, **settings), region, service)

    def test_hostname_inference_ignores_port(self):
        self.assert_scope(
            self.sign('s3.eu-west-2.amazonaws.com:8443'), 'eu-west-2', 's3',
        )

    def test_host_override_does_not_change_endpoint_inference(self):
        self.assert_scope(
            self.sign('s3.eu-west-2.amazonaws.com', host='custom.example.com'),
            'eu-west-2', 's3',
        )

    def test_unrecognized_endpoints_require_explicit_settings(self):
        for host in [
            'custom.example.com',
            'abc.lambda-url.eu-west-2.on.aws',
            'bucket.s3.amazonaws.com',
            'custom.foo.eu-west-2.amazonaws.com',
            'ec2.dualstack.eu-west-2.amazonaws.com',
            's3.eu-west-2.amazonaws.com.example.com',
            's3.eu--2.amazonaws.com',
            's3.eu-west-two.amazonaws.com',
            's3.e-west-2.amazonaws.com',
            's3.eu-123-2.amazonaws.com',
        ]:
            with self.subTest(host=host):
                with self.assertRaisesRegex(ValueError,
                                            'AWS region.*manually'):
                    self.sign(host)
                with self.assertRaisesRegex(ValueError,
                                            'AWS service.*manually'):
                    self.sign(host, region='eu-west-2')
                with self.assertRaisesRegex(ValueError,
                                            'AWS region.*manually'):
                    self.sign(host, service='s3')
                self.assert_scope(
                    self.sign(host, region='eu-west-2', service='s3'),
                    'eu-west-2', 's3',
                )


if __name__ == '__main__':
    unittest.main()
