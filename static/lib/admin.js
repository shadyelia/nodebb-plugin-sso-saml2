'use strict';

$(document).ready(function() {
	require(['settings', 'alerts'], function(Settings, alerts) {
		const wrapper = $('.sso-saml-settings');
		
		Settings.load('sso-saml', wrapper);
		
		$('#save').on('click', function(e) {
			e.preventDefault();
			
			Settings.save('sso-saml', wrapper, function() {
				alerts.success('Settings saved successfully!');
			});
		});
	});
});