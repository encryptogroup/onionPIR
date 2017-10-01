/*
  PIRchat - A web based chat client for onionpir
  Copyright (C) 2014 PIRchat authors and contributers

  This file is part of PIRchat.

  PIRchat is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  PIRchat is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with PIRchat.  If not, see <http://www.gnu.org/licenses/>.
*/

(function() {
  var app = angular.module('pirchat', ['fullscreen', 'notifications', 'websocket']);

  app.controller('pirchatCtrl', ['$scope', '$http', 'Fullscreen', 'Notifications', 'WS', function($scope, $http, FullscreenService, Notifications, WS) {
    'use strict';

    $scope.goFullscreen = FullscreenService.goFullscreen;

    $scope.notImplemented = function() {
      alert("This feature is not implemented yet. :( Sorry.");
    };

    // == initialise scope ==
    $scope.active_mainview = 'welcome';
    $scope.profile = {
      username: "Loading...",
      status_msg: "Loading..."
    };
    $scope.contacts = [];
    $scope.activecontactindex = -1;
    $scope.messagetosend = '';
    $scope.friendRequests = [];
    $scope.new_friend_request = {
      friend_id: '',
      message: '',
    };
    $scope.settings = {};
    $scope.curDate = Date.now(); // current unix timestap used to work around caching

    var getContactIndexByNum = function(id) {
      for (var i in $scope.contacts)
        if ($scope.contacts[i].id === id) return i;
      return -1;
    };

    $scope.setUsername = function(username) {
      $http.post('api/post/username', "username=" + username, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }).success(function() {
        fetchProfile();
      }).error(function() {
        fetchProfile();
      });
    };

    $scope.setStatusMsg = function(status_msg) {
      $http.post('api/post/statusmessage', "status=" + status_msg, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }).success(function() {
        fetchProfile();
      }).error(function() {
        fetchProfile();
      });
    };

    $scope.setUserStatus = function(status) {
      $http.post('api/post/status', {
        status: status
      }).success(function() {
        fetchProfile();
      }).error(function() {
        fetchProfile();
      });
    };

    $scope.showChat = function(id) {
      var i = getContactIndexByNum(id);
      if (i != -1) {
        $scope.activecontactindex = i;
        $scope.active_mainview = 'chat';
        $scope.contacts[i].last_msg_read = Date.now();

        window.setTimeout(function() {
          $("#mainview-chat-body").scrollTop($("#mainview-chat-body").prop("scrollHeight"));
        }, 10);
      }
    };

    $scope.scrollLeft = function() {
      if ($(window).width() < 768) {
        $('#profile-card, #contact-list-wrapper, #button-panel').addClass('translate75left');
        $('#mainview').addClass('translate100left');
        $('#profile-card-back-button').show();
      }
    };

    // == Settings ==
    $scope.showSettings = function() {
      $scope.active_mainview = 'settings';
    };

    // == Demonstator Mode ==
    $scope.showDemo = function() {
      $scope.active_mainview = 'demo';
    };

    // == Messages ==
    $scope.sendMessage = function() {
      if ($scope.messagetosend.length === 0)
        return false;

      $http.post('api/post/message', "contact_id=" +
        encodeURIComponent($scope.contacts[$scope.activecontactindex].id) +
        "&msg="+encodeURIComponent($scope.messagetosend), {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }).success(function(data) {
        if (data.status == "failure") {
          alert(data.reason);
        } else {
          $scope.contacts[$scope.activecontactindex].chat.unshift({
            "isIncoming": false,
            "isAction": false,
            "message": $scope.messagetosend.replace(/\n/g, "<br>"),
            "time": Date.now()
          });
        }
        $scope.messagetosend = '';
      }).error(function() {
        alert("Error: Internal server error.");
      });

      $scope.contacts[$scope.activecontactindex].last_msg_read = Date.now()+1000;

      $("#mainview-chat-body").animate({
        "scrollTop": $("#mainview-chat-body").prop("scrollHeight")
      }, 1000);
    };

    // == Demonstrator mode ==
    $scope.doPIRrequest = function(){
      $http.get('api/get/contactlist').success(function() {
        alert('Done');
      });
    };


    // == Friends ==
    $scope.sendFriendRequest = function(mail) {
      $http.post('api/post/friend_request', "mail=" + mail, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }).success(function(data) {
        console.log(data);
        if (data.status != "success") {
          alert(data.reason);
        }
        $('#modal-friend-requests').modal('hide');
        $http.get('api/get/contactlist').success(function(data) {
          $scope.contacts = data;
        });


      }).error(function(err) {
        alert("Internal server error.");
      });
    };

    $scope.toggleFriendRequestBody = function(){
      $(this)[0].friendRequest.is_ignored = !$(this)[0].friendRequest.is_ignored;
    };


    // == Event handlers ==
    $('#profile-card-back-button').click(function() {
      $('#profile-card, #contact-list-wrapper, #button-panel').removeClass('translate75left');
      $('#mainview').removeClass('translate100left');
      $('#profile-card-back-button').hide();
    });

    $("#mainview-chat-footer-textarea-wrapper textarea").keyup(function(event) {
      if (event.which == 13 && event.shiftKey !== true) {
        $scope.sendMessage();
      }
    });

    $('#inputAuthUser').change(function() {
      $(this).parent().next().find('button').show();
    }).keyup(function() {
      $(this).parent().next().find('button').show();
    }).parent().next().find('button').click(function() {
      $http.post('api/post/settings_auth_user', {
        username: $('#inputAuthUser').val()
      }).success(function() {
        $('#inputAuthUser').parent().next().find('button').hide();
      });
    });

    $('#inputAuthPass').change(function() {
      $(this).parent().next().find('button').show();
    }).keyup(function() {
      $(this).parent().next().find('button').show();
    }).parent().next().find('button').click(function() {
      $http.post('api/post/settings_auth_pass', {
        password: $('#inputAuthPass').val()
      }).success(function() {
        $('#inputAuthPass').parent().next().find('button').hide();
        $('#inputAuthPass').val('');
      });
    });

    $('#checkbox-notifications').change(function() {
      $http.post('api/post/keyValue', {
        key: 'settings_notifications_enabled',
        value: $('#checkbox-notifications').prop('checked').toString()
      }).error(function() {
        fetchSettings();
      });
    });

    $('#checkbox-away-on-disconnect').change(function() {
      $http.post('api/post/keyValue', {
        key: 'settings_away_on_disconnect',
        value: $('#checkbox-away-on-disconnect').prop('checked').toString()
      }).error(function() {
        fetchSettings();
      });
    });


    // == fetch data from the server ==
    var fetchSettings = function() {
      $http.get('api/get/settings').success(function(data) {
        $scope.settings = data;
      });
    };

    var fetchProfile = function() {
      $http.get('api/get/profile').success(function(data) {
        $scope.profile = data;
      }).error(function(){
        location.href = "/";
      });
    };

    var fetchContactlist = function() {
      $http.get('api/get/contactlist').success(function(data) {
        $scope.contacts = data;
      });
    };


    // == WebSocket connection ==
    WS.registerHandler('friend_message', function(msg) {
      console.log(msg.data);
      var i = getContactIndexByNum(msg.data.friend);
      if (i >= 0 && i < $scope.contacts.length) {
        console.log($scope.contacts[i]);
        $scope.contacts[i].chat.unshift({
          "message": msg.data.message,
          "isIncoming": true,
          "isAction": msg.data.isAction,
          "time": msg.data.time
        });
        if ($scope.settings.notifications_enabled) {
          Notifications.show($scope.contacts[i].name, msg.data.message, "friend_message"+$scope.contacts[i].number, function() {
            $scope.showChat(msg.data.friend);
          });
        }

        $("#mainview-chat-body").animate({
          "scrollTop": $("#mainview-chat-body").prop("scrollHeight")
        }, 1000);
      }
    });

    WS.registerHandler('profile_update', fetchProfile);
    WS.registerHandler('friendlist_update', fetchContactlist);

    WS.registerHandler('avatar_update', function() {
      $scope.curDate = Date.now(); // reload avatar images
    });

    var onopen = function(event) {
      console.log("WebSocket connection established.");
      $('#modal-connection-error').modal('hide');
      fetchProfile();
      fetchContactlist();
      //fetchSettings();
      $scope.$apply();
    };

    var onclose = function() {
      console.log("WebSocket connection closed!");
      $('.modal.info, .modal.warning').modal('hide');
      $('#modal-connection-error').modal('show');
      window.setTimeout($scope.ws_create, 2000);
    };

    WS.newConnection(onopen, onclose);

  }]);
})();
