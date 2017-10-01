(function() {
  $('#registration-mail-form').on('submit', function(){
    var mail = $("#registration-mail").val();
    $('#log').append("<p>Requesting token for mail address "+mail+"...</p>");
    var jqxhr = $.post('/api/register/request_token', {
      mail: mail
    }).done(function(response){
      if (response == "success") {
        $('#registration-mail-form input').prop('enabled', false);
        $('#section-registration-token').show();
        $('#log').append("<p>Token requested.</p>");
      } else if (response == 'invalid_mail') {
        alert("Invalid mail address. This mail address is already in use.");
      } else {
        alert("Unknown error. :(");
      }
    });

    return false;
  });

  $('#registration-token-form').on('submit', function(){
    $('#log').append("<p>Sending token to server...</p>");
    var mail = $("#registration-mail").val();
    var token = $("#registration-token").val();
    var jqxhr = $.post('/api/register/verify_token', {
      mail: mail,
      token: token
    }).success(function(response){
      console.log(response);
      if (response == "success") {
        $('#log').append("<p>Token valid.</p>");
        window.setTimeout(function(){
          $('#log').append("<p>Uploading public key to server...</p>");
          window.setTimeout(function(){
            $('#log').append("<p>Done. Loading user interface.</p>");
            location.href = 'chat.html'
          }, 1000);
        }, 1000);
      } else {
        alert(response);
      }
    }).error(function(){
      alert("Internal server error.")
    });

    return false;
  });
})();
