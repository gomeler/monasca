# Stub

import logging
import pdb
import six
import time
import requests
import warnings
import json
from requests.packages.urllib3 import exceptions

import monasca_agent.collector.checks as checks

LOG = logging.getLogger(__name__)


class SolidFire(checks.AgentCheck):

    def __init__(self, name, init_config, agent_config):
        super(SolidFire, self).__init__(name, init_config, agent_config)
        self.sf = None

    def check(self, instance):
        """ Pull down cluster stats.
        """
        dimensions = self._set_dimensions(None, instance)
        LOG.info("DIMENSIONS: {}".format(dimensions))
        data = {}
        num_of_metrics = 0
        # Extract cluster auth information
        auth = self._pull_auth(instance)
        self.sf = SolidFireLib(auth)

        res = self._get_cluster_stats()
        data.update(res)  

        # Dump data
        for key, value in data.iteritems():
            if data[key] is None:
                continue
            self.gauge(key, value, dimensions)
            num_of_metrics += 1

        LOG.info("Collected {} metrics".format(num_of_metrics))

    def _pull_auth(self, instance):
        # TODO: Add verification that all fields populated
        auth = {'mvip': instance.get('mvip'),
                'port': instance.get('port', 443),
                'login': instance.get('username'),
                'passwd': instance.get('password')}
        auth['url'] = 'https://%s:%s' % (auth['mvip'],
                                         auth['port'])

        return auth

    def _get_cluster_stats(self):
        res = self.sf._issue_api_request('GetClusterStats', {}, '8.0')['result']['clusterStats']
        data = {'cluster.clusterUtilization': res['clusterUtilization'],
                'cluster.clientQueueDepth': res['clientQueueDepth']}
        return data


def retry(exc_tuple, tries=5, delay=1, backoff=2):
    # Retry decorator used for issuing API requests.
    def retry_dec(f):
        @six.wraps(f)
        def func_retry(*args, **kwargs):
            _tries, _delay = tries, delay
            while _tries > 1:
                try:
                    return f(*args, **kwargs)
                except exc_tuple:
                    time.sleep(_delay)
                    _tries -= 1
                    _delay *= backoff
                    LOG.debug('Retrying %(args)s, %(tries)s attempts '
                              'remaining...',
                              {'args': args, 'tries': _tries})
            # NOTE(jdg): Don't log the params passed here
            # some cmds like createAccount will have sensitive
            # info in the params, grab only the second tuple
            # which should be the Method
            msg = ('Retry count exceeded for command: %s' %
                  (args[1]))
            LOG.error(msg)
            raise Exception(msg)
        return func_retry

class SolidFireLib():
    def __init__(self, auth):
        self.endpoint = auth
        self.active_cluster_info = {}

        self._set_active_cluster_info(auth)



    retryable_errors = ['xDBVersionMismatch',
                        'xMaxSnapshotsPerVolumeExceeded',
                        'xMaxClonesPerVolumeExceeded',
                        'xMaxSnapshotsPerNodeExceeded',
                        'xMaxClonesPerNodeExceeded',
                        'xNotReadyForIO']

    retry_exc_tuple = (requests.exceptions.ConnectionError)

    @retry(retry_exc_tuple, tries=6)
    def _issue_api_request(self, method, params, version='1.0', endpoint=None):
        if params is None:
            params = {}
        if endpoint is None:
            endpoint = self.active_cluster_info['endpoint']

        payload = {'method': method, 'params': params}
        url = '%s/json-rpc/%s/' % (endpoint['url'], version)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", exceptions.InsecureRequestWarning)
            req = requests.post(url,
                                data=json.dumps(payload),
                                auth=(endpoint['login'], endpoint['passwd']),
                                verify=False,
                                timeout=30)
        response = req.json()
        req.close()
        if (('error' in response) and
                (response['error']['name'] in self.retryable_errors)):
            msg = ('Retryable error (%s) encountered during '
                   'SolidFire API call.' % response['error']['name'])
            LOG.debug(msg)
            raise Exception(message=msg)

        if 'error' in response:
            msg = ('API response: %s') % response
            raise Exception(msg)

        return response


    def _set_active_cluster_info(self, endpoint):
        self.active_cluster_info['endpoint'] = endpoint

        for k, v in self._issue_api_request(
                'GetClusterInfo',
                {})['result']['clusterInfo'].items():
            self.active_cluster_info[k] = v

        # Add a couple extra things that are handy for us
        self.active_cluster_info['clusterAPIVersion'] = (
            self._issue_api_request('GetClusterVersionInfo',
                                    {})['result']['clusterAPIVersion'])
        LOG.info("Set the endpoint")
        LOG.info("{}".format(self.active_cluster_info))
