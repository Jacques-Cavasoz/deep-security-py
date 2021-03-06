''' Filters are used for parsing down data retrieved from the Deep Security
	Manager. Different event types require different filter types or 
	different variables as defined by the SOAP or REST API.
'''
EnumHostType = [
	'STANDARD',
	'ESX',
	'APPLIANCE',
	'VM'
]
EnumHostDetailLevel = [
	'HIGH', 
	'MEDIUM', 
	'LOW'
]

EnumHostFilterType = [
	'ALL_HOSTS', 
	'HOSTS_IN_GROUP', 
	'HOSTS_USING_SECURITY_PROFILE', 
	'HOSTS_IN_GROUP_AND_ALL_SUBGROUPS', 
	'SPECIFIC_HOST', 
	'MY_HOSTS'
]

EnumTimeFilterType = [
	'LAST_HOUR', 
	'LAST_24_HOURS', 
	'LAST_7_DAYS', 
	'CUSTOM_RANGE', 
	'SPECIFIC_TIME', 
	'PREVIOUS_MONTH'
]

EnumOperator = [
	'GREATER_THAN', 
	'LESS_THAN', 
	'EQUAL'
]

EnumTagFilterType = [
	'ALL', 
	'UNTAGGED', 
	'TAGS'
]

EnumExternalFilterType = [
	'ALL_EXT_HOSTS', 
	'HOSTS_IN_EXT_GROUP', 
	'SPECIFIC_EXT_HOST',
	'HOSTS_IN_EXT_GROUP_AND_ALL_SUBGROUPS'
]

RestEnumOperator = [
	'GT', # Greater than
	'GE', # Greater than or equal to
	'EQ', # Equal to
	'LT', # Less than
	'LE'  # Less than or equal to
]


def _format_and_validate_operator(op, valid_ops):
	op = op.upper()
	assert op in valid_ops, 'Valid operators: %s' % ', '.join(valid_ops)
	return op

def create_host_filter(hostGroupID=None, hostID=None, securityProfileID=None, 
					   operator='ALL_HOSTS'):
	''' HostFilterTransport object. Used as search criteria to limit the scope of
		objects returned by computer-related attributes, such as by a Group, a 
		Security Profile, or a specific computer. The event retrieval related methods
	    will require a HostFilterTransport that is empty to search for all events, or 
		with specific properties populated to limit the scope of the search. For 
		example, setting the HostFilterTransport securityProfileID property to 
		the ID of a Security Profile will limit any event retrieval method calls to 
		events that pertain to computers with the specific SecurityProfile assigned.
		
		hostGroupID - int - The ID of the host group by which to filter
		hostID - int - The ID of the host by which to filter
		securityProfileID - int - The ID of the security profile by which to filter
		type - EnumHostFilterType - The operator by which to filter
	'''
	return {
		'hostGroupID': hostGroupID,
		'hostID': hostID,
		'securityProfileID': securityProfileID,
		'type': _format_and_validate_operator(operator, EnumHostFilterType)
	}

def create_time_filter(rangeFrom=None, rangeTo=None, specificTime=None, 
					   operator='LAST_7_DAYS'):
	''' TimeFilterTransport object. Used as search criteria limit the scope of
		objects returned by time related attributes, such as from, to, or a
		specific time. If the type is set to CUSTOM_RANGE, then the rangeFrom
		and rangeTo property will be required. If the SPECIFIC_TIME type is 
		set, then the specifiicTime property will be required.

		rangeFrom - dateTime - 
		rangeTo - dateTime - 
		specificTime - dateTime - 
		type - EnumTimeFilterType - Operator by which to filter
	'''
	return {
		'rangeFrom': rangeFrom,
		'rangeTo': rangeTo,
		'specificTime': specificTime,
		'type': _format_and_validate_operator(operator, EnumTimeFilterType)
	}

def create_id_filter(eventID=0, operator='GREATER_THAN'):
	''' IDFilterTransport object. Used as a search criteria to limit the scope
		of objects returned by event transport object ID. Each event transport 
		object, such as IntegrityEventTransport, includes an ID property that 
		is assigned as the primary key of an event when it is generated by a 
		computer agent. It is possible to filter event retrieval by this event
	    ID in order to retrieve a specific event by ID, or events that are 
		greater or less than a specified ID. For example, a utility that is 
		designed to retrieve all new events on an interval can use the event
		ID property to uniquely identify which events have already been 
		retrieve`d. This way retrieval of duplicate events can be avoided.

		id - long - The ID of the host by which to filter the request.
		operator - EnumOperator - Operator by which to filter
	'''
	return {
		'id': long(eventID),
		'operator': _format_and_validate_operator(operator, EnumOperator)
	}

def create_tag_filter(tags=None, operator='ALL'):
	''' TagFilterTransport object. Used as a search criteria to specify the
		criteria of tags for the search.

		tags - string - The requested tags, depending on the type of field.
		type - EnumTagFilterType - ALL returns an unbounded set, UNTAGGED
								   returns only events that have no tags. 
								   Otherwise the tags field is a freeform 
								   field that takes comma delimited tag names
								   (with the not '!' character indicated where
								   not tagged).
	'''
	return {
		'tags': tags,
		'type': _format_and_validate_operator(operator, EnumTagFilterType)
	}

def create_external_filter(hostExternalID=None, hostGroupExternalID=None, 
						   operator='ALL_EXT_HOSTS'):
	''' ExternalFilterTransport object. A filter that can be used to filter
		by the ExternalID field of a host or host group

		hostExternalID - string - The ID of the host by which to filter
		hostGroupExternalID - string - The ID of the host group by which to filter
		type - EnumExternalFilterType - The operator by which to filter
	'''
	return {
		'hostExternalID': str(hostExternalID),
		'hostGroupExternalID': str(hostGroupExternalID),
		'type': _format_and_validate_operator(operator, EnumExternalFilterType)
	}

def create_rest_event_filter(eventId=None, eventIdOp='EQ', eventTime=None, 
							 eventTimeOp='EQ', maxItems=None):
	''' REST call will pass the key/pair values on the query string to
		filter the data returned.

		eventId - int - ID of a specific event for which to query. Combined with
						eventIDOp, the returning events can be filtered 
						according to the ID.
		eventIdOp - string - Define the events to return. Currently supported 
							 operations include GT, GE, EQ, LT, and LE. Default
						    is 'eq'.
		eventTime - time - The event time to query for events. Represented by a
						   long integer, which is the milliseconds since 
						   January 1, 1970, 00:00:00 GMT. Combined with 
						   eventTimeOp, the returning events can be filtered by
						   the specific milliseconds. Please be aware that for 
						   integrity events, the accuracy of event time is 
						   millisecond. In other words, if you want to exactly
						   filter events by event time, the eventTime value
						   must be millisecond accuracy.
		eventTimeOp - string - Define the events to return. Currently supported
							   operations include GT, GE, EQ, LT, and LE.
							   Default is 'eq'.
		maxItems - int - The maximum events to return. 1 is minimum valid value
	'''
	maxItems = int(maxItems)
	filter = {
		'eventId': eventId,
		'eventIdOp': None,
		'eventTime': eventTime,
		'eventTimeOp': None,
		'maxItems': maxItems if maxItems >= 1 else 1 
	}
	if eventIdOp:
		op = _format_and_validate_operator(eventIdOp, RestEnumOperator)
		filter['eventIdOp'] = op
	
	if eventTimeOp:
		op = _format_and_validate_operator(eventTimeOp, RestEnumOperator)
		filter['eventTimeOp'] = op
	return filter
