jQuery(function($){
	$(document).ready(function(){
		var GA_pwdenabled = parseInt($('#GA_pwdenabled').val());
		if ( 1 == GA_pwdenabled ) {
			$('#GA_DEACTIVE_APP_PASSWORD').slideDown();
			$('#GA_GENERATE_APP_PASSWORD').slideUp();

			$('#GA_APP_PASSWORD').text('Deactive');
		} else {
			$('#GA_DEACTIVE_APP_PASSWORD').slideUp();
			$('#GA_GENERATE_APP_PASSWORD').slideDown();

			$('#GA_APP_PASSWORD').text('Create New Password');
		}
	});

	$('#GA_APP_PASSWORD').click(function(e){
		e.preventDefault();

		var el = $(this);

		var dataForm = $(this).closest('form').serialize();

		var dataPost = {
			'action': 'remote_GA_app_password', 
			'dataForm': dataForm 
		};

		$.ajax({
			url: ajaxurl, 
			type: 'POST', 
			data: dataPost, 
			dataType: 'json', 
			success: function(response){
				console.log(response); 
				
				var json_data = response.data, 
					status = json_data.status;

				console.log(status);

				if ( 'active' == status ) {
					el.text('Deactive');
					$("#GA_APP_PASSWORD_STATUS").text('Active');
					$('#GA_PASSWORD_BOX').show('slow');
					$('#GA_pwdenabled').val(1);
					$('#GA_password').val(json_data.app_password);
					$('#GA_passworddesc').show('slow');
				} else {
					el.text('Create New Password');
					$("#GA_APP_PASSWORD_STATUS").text('Not Active');
					$('#GA_PASSWORD_BOX').hide();
					$('#GA_pwdenabled').val(0);
					$('#GA_password').val('XXXX XXXX XXXX XXXX');
					$('#GA_passworddesc').hide();
				}
			},
			complete: function(jqXHR, status){
				if ( 'success' == status ) {}
			}
		});
	});

	$('#GA_GENERATE_APP_PASSWORD').click(function(e){
		e.preventDefault();

		var el = $(this);

		var dataForm = $(this).closest('form').serialize();

		var dataPost = {
			'action': 'remote_generate_GA_app_password', 
			'dataForm': dataForm 
		};

		$.ajax({
			url: ajaxurl, 
			type: 'POST', 
			data: dataPost, 
			dataType: 'json', 
			success: function(response){
				console.log(response); 
				
				var json_data = response.data;

				$('#GA_password').val(json_data.app_password);
				$('#GA_passworddesc').show('slow');
			},
			complete: function(jqXHR, status){
				el.slideUp('slow');
				$("#GA_APP_PASSWORD_STATUS").text('Active');
				$('#GA_PASSWORD_BOX').show('slow');
				$("#GA_DEACTIVE_APP_PASSWORD").slideDown('slow');
			}
		});
	});

	$('#GA_DEACTIVE_APP_PASSWORD').click(function(e){
		e.preventDefault();

		var el = $(this);

		var dataForm = $(this).closest('form').serialize();

		var dataPost = {
			'action': 'remote_deactive_GA_app_password', 
			'dataForm': dataForm 
		};

		$.ajax({
			url: ajaxurl, 
			type: 'POST', 
			data: dataPost, 
			dataType: 'json', 
			success: function(response){
				console.log(response); 

				var json_data = response.data;

				$('#GA_password').val('XXXX XXXX XXXX XXXX');
				$('#GA_passworddesc').hide('slow');
			},
			complete: function(jqXHR, status){
				if ( 'success' == status ) {
					el.slideUp('slow');
					$("#GA_APP_PASSWORD_STATUS").text('Not Active');
					$('#GA_PASSWORD_BOX').hide('slow');
					$("#GA_GENERATE_APP_PASSWORD").slideDown('slow');
				}
			}
		});
	});
});
