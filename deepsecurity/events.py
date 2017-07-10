''' Retrieve events using either SOAP (default) or REST API. Not all events can
	be retrieved via the REST API. Currently, Application Control events can
	only be retrieved via REST API. All events support various types of filters.
	To reduce the number of variables passed in to the event retrieval classes,
	the caller should build the filter and then pass it in.

	The total number of events which can be retrieved by a single call is
	limited by how many items can be retrieved from the database for the user
	account utilized by the API. If the user account can only retrieve 5,000
	items from the database and there are 50,000 events, 10 separate calls will
	be required. Alternatively, the maximum number of items which can be
	retrieved from the database can be increased on the Deep Security Manager.

	Filters are used to parse down the number of events returned. In Pyhon,
	filters are simply dictionaries of key/value pairs. Each filter corresponds
	to a FilterTransport object.
'''

import core
import filters


def _build_call_parms(time_filter=None, host_filter=None, id_filter=None,
					  rest_filter=None, ext_parms=None, REST_API=False):
	''' SOAP and REST API event retrieval parameters use different filter
		values but are all dictionaries of key/value pairs. For example, all
		SOAP event retrieval methods use a dictionary of time, host, and
		eventID filters. REST API event retrieval methods use a single
		dictinary of parameters by which to filter.
	'''
	parms = dict()
	if REST_API:
		parms.update(
			rest_filter or filters.create_rest_event_filter(eventId=0, eventIdOp='GT')
		)
	else:
		time_filter = time_filter if time_filter else filters.create_time_filter()
		host_filter = host_filter if host_filter else filters.create_host_filter()
		id_filter = id_filter if id_filter else filters.create_id_filter()
		parms.setdefault('timeFilter', time_filter)
		parms.setdefault('hostFilter', host_filter)
		parms.setdefault('eventIdFilter', id_filter)
	if isinstance(ext_parms, dict):
		parms.update(ext_parms)
	return parms


def _make_call(entrypoint, manager, call_data=None, call_query=None, 
			   REST_API=False, cookieAuth=True):
	''' The type of API method being used determines the how the request is 
		formatted and what type of authentication is used.

		Request format is a dictionary with the following key/value pairs:
		{
			'api': 'REST' or 'SOAP',
			'call': <API Entrypoint>,
			'use_cookie_auth': BOOL,
			'query': None,
			'data': None,
		}
	'''
	_core = core.CoreApi()
	req = manager._get_request_format(
		api=_core.API_TYPE_REST if REST_API else _core.API_TYPE_SOAP,
		call=entrypoint, 
		use_cookie_auth=cookieAuth
	)
	req['query'] = call_query
	req['data'] = call_data
	resp = manager._request(req)
	if resp and resp['status'] == 200 and not isinstance(resp['data'], list):
		resp['data'] = [resp['data']]
	return resp


class _Event(core.CoreObject):
	''' Convert the API keypairs to object properties.
	'''
	def __init__(self, event, log_func):
		self._set_properties(event, log_func)


class SystemEvents(core.CoreDict):
	''' Retrieve System Events from the Deep Security Manager. Events can only
		be retrieved via the SOAP API.

		Usage:
			time_filter - If None, events for the last 7 days will be retrieved
			host_filter - If None, events for all hosts will be retrieived.
			id_filter - If None, all events greater than 0 will be retrieved.
			includeNonHostevents - Boolean to specify retrieval non-host events
	'''
	def __init__(self, manager=None):
		core.CoreDict.__init__(self)
		self.manager = manager
		self.log = self.manager.log if self.manager else None

	def get(self, time_filter=None, host_filter=None, id_filter=None, 
			includeNonHostevents=True):
		response = _make_call(
			'systemEventRetrieve2', 
			self.manager,
		    call_data=_build_call_parms(
				time_filter, 
				host_filter, 
				id_filter, 
				ext_parms={
					'includeNonHostEvents': includeNonHostevents
				}
			)
		)
		for event in response['data'][0]['systemEvents']:
			self[event['systemEventID']] = _Event(event, self.log)
		return len(self)


class AntiMalwareEvents(core.CoreDict):
	''' Retrieve AntiMalware Events from the Deep Security Manager. Events can
		be retrieved via either the SOAP or REST API methods.

		Usage - SOAP:
			time_filter - If None, events for the last 7 days will be retrieved
			host_filter - If None, events for all hosts will be retrieived.
			id_filter - If None, all events greater than 0 will be retrieved.

		Usage - REST:
			rest_filter - If None, all available events will be retrieved.
	'''
	def __init__(self, manager=None):
		core.CoreDict.__init__(self)
		self.manager = manager
		self.log = self.manager.log if self.manager else None

	def get(self, time_filter=None, host_filter=None, id_filter=None, 
			rest_filter=None, REST_API=False):
		if REST_API:
			response = _make_call(
				'events/antimalware', 
				self.manager, 
				call_query=_build_call_parms(
					rest_filter=rest_filter, 
					REST_API=REST_API
				), 
				REST_API=REST_API, 
				cookieAuth=False
			)
			events = response['data'][0]['antiMalwareEventListing']['events']
		else:
			response = _make_call(
				'antiMalwareEventRetrieve2', 
				self.manager,
				call_data=_build_call_parms(
					time_filter, 
					host_filter, 
					id_filter
				)
			)
			events = response['data'][0]['antiMalwareEvents']
		for event in events:
			self[event['antiMalwareEventID']] = _Event(event, self.log)
		return len(self)


class WebReputationEvents(core.CoreDict):
	''' Retrieve Web Reputation Events from the Deep Security Manager. Events 
		can be retrieved via either the SOAP or REST API methods.

		Usage - SOAP:
			time_filter - If None, events for the last 7 days will be retrieved
			host_filter - If None, events for all hosts will be retrieived.
			id_filter - If None, all events greater than 0 will be retrieved.

		Usage - REST:
			rest_filter - If None, all available events will be retrieved.
	'''
	def __init__(self, manager=None):
		core.CoreDict.__init__(self)
		self.manager = manager
		self.log = self.manager.log if self.manager else None

	def get(self, time_filter=None, host_filter=None, id_filter=None, 
			rest_filter=None, REST_API=False):
		if REST_API:
			response = _make_call(
				'events/webreputation', 
				self.manager, 
				call_query=_build_call_parms(
					rest_filter=rest_filter, 
					REST_API=REST_API
				), 
				REST_API=REST_API, 
				cookieAuth=False
			)
			events = response['data'][0]['WebReputationEventListing']['WebReputationEvent']
		else:
			response = _make_call(
				'webReputationEventRetrieve2', 
				self.manager, 
				call_data=_build_call_parms(
					time_filter, 
					host_filter, 
					id_filter
				)
			)
			events = response['data'][0]['webReputationEvents']
		for event in events:
			self[event['webReputationEventID']] = _Event(event, self.log)
		return len(self)


class FirewallEvents(core.CoreDict):
	''' Retrieve Firewall Events from the Deep Security Manager. Events
		can only be retrieved via the SOAP API.

		Usage:
			time_filter - If None, all events for the last 7 days will be retrieved.
			host_filter - If None, events for all hosts will be retrieived.
			id_filter - If None, all events greater than 0 will be retrieved.
	'''
	def __init__(self, manager=None):
		core.CoreDict.__init__(self)
		self.manager = manager
		self.log = self.manager.log if self.manager else None

	def get(self, time_filter=None, host_filter=None, id_filter=None):
		response = _make_call(
			'firewallEventRetrieve2', 
			self.manager, 
			call_data=_build_call_parms(
				time_filter, 
				host_filter, 
				id_filter
			)
		)
		for event in response['data'][0]['firewallEvents']:
			self[event['firewallEventID']] = _Event(event, self.log)
		return len(self)


class IntrusionPreventionEvents(core.CoreDict):
	''' Retrieve Intrusion Prevention Events from the Deep Security Manager. 
		Events can only be retrieved via the SOAP API.

		Usage:
			time_filter - If None, events for the last 7 days will be retrieved
			host_filter - If None, events for all hosts will be retrieived.
			id_filter - If None, all events greater than 0 will be retrieved.
	'''
	def __init__(self, manager=None):
		core.CoreDict.__init__(self)
		self.manager = manager
		self.log = self.manager.log if self.manager else None

	def get(self, time_filter=None, host_filter=None, id_filter=None):
		response = _make_call(
			'DPIEventRetrieve2', 
			self.manager, 
			call_data=_build_call_parms(
				time_filter, 
				host_filter, 
				id_filter
			)
		)
		for event in response['data'][0]['DPIEvents']:
			self[event['intrusionEventID']] = _Event(event, self.log)
		return len(self)


class IntegrityMonitoringEvents(core.CoreDict):
	''' Retrieve Integrity Monitoring Events from the Deep Security Manager. 
		Events can be retrieved via either the SOAP or REST API methods.

		Usage - SOAP:
			time_filter - If None, events for the last 7 days will be retrieved
			host_filter - If None, events for all hosts will be retrieived.
			id_filter - If None, all events greater than 0 will be retrieved.

		Usage - REST:
			rest_filter - If None, all available events will be retrieved.
			extendedDesc - Bool, provide more information about the affected 
						   entities and related attributes. By default, SOAP
						   provides extended information. By default, REST does
						   not.For consistency with the SOAP method, this 
						   filter is defaulted to True.
	'''
	def __init__(self, manager=None):
		core.CoreDict.__init__(self)
		self.manager = manager
		self.log = self.manager.log if self.manager else None

	def get(self, time_filter=None, host_filter=None, id_filter=None, 
			rest_filter=None, extendedDesc=True, REST_API=False):
		if REST_API:
			response = _make_call(
				'events/integrity', 
				self.manager, 
				call_query=_build_call_parms(
					rest_filter=rest_filter, 
					ext_parms={
						'extendedDesc': extendedDesc
					}
				), 
				REST_API=REST_API
			)
			for event in response['data'][0]['ListEventsResponse']['events']:
				self[event['eventID']] = _Event(event, self.log)
		else:
			response = _make_call(
				'IntegrityEventRetrieve2', 
				self.manager, 
				call_data=_build_call_parms(
					time_filter, 
					host_filter, 
					id_filter
				)
			)
			data = response['data'][0]['integrityEventRetrieve2Return']
			for event in data['integrityEvents']:
				self[event['integrityEventID']] = _Event(event, self.log)
		return len(self)


class LogInspectionEvents(core.CoreDict):
	''' Retrieve Log Inspection Events from the Deep Security Manager. Events can 
		be retrieved via either the SOAP or REST API methods.

		Usage - SOAP:
			time_filter - If None, events for the last 7 days will be retrieved
			host_filter - If None, events for all hosts will be retrieived.
			id_filter - If None, all events greater than 0 will be retrieved.

		Usage - REST:
			rest_filter - If None, all available events will be retrieved.
	'''
	def __init__(self, manager=None):
		core.CoreDict.__init__(self)
		self.manager = manager
		self.log = self.manager.log if self.manager else None

	def get(self, time_filter=None, host_filter=None, id_filter=None, 
			rest_filter=None, REST_API=False):
		if REST_API:
			response = _make_call(
				'events/logInspection', 
				self.manager, 
				call_query=_build_call_parms(
					rest_filter=rest_filter, 
					REST_API=REST_API
				), 
				REST_API=REST_API
			)
			for event in response['data'][0]['ListEventsResponse']['events']:
				self[event['eventID']] = _Event(event, self.log)
		else:
			response = _make_call(
				'logInspectionEventRetrieve2', 
				self.manager, 
				call_data=_build_call_parms(
					time_filter, 
					host_filter, 
					id_filter
				)
			)
			for event in response['data'][0]['logInspectionEvents']:
				self[event['logInspectionEventID']] = _Event(event, self.log)
		return len(self)


class ApplicationControlEvents(core.CoreDict):
	''' Retrieve Application Control Events from the Deep Security Manager.
		Events can only be retrieved via the REST API.

		Usage:
			rest_filter - If None, all available events will be retrieved.
	'''
	def __init__(self, manager=None):
		core.CoreDict.__init__(self)
		self.manager = manager
		self.log = self.manager.log if self.manager else None

	def get(self, rest_filter=None):
		response = _make_call(
			'events/appcontrol', 
			self.manager, 
			call_query=_build_call_parms(
				rest_filter=rest_filter, 
				REST_API=True
			), 
			REST_API=True
		)
		for event in response['data'][0]['ListEventsResponse']['events']:
			self[event['eventID']] = _Event(event, self.log)
		return len(self)
