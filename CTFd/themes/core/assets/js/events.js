import { Howl } from "howler";
import { NativeEventSource, EventSourcePolyfill } from "event-source-polyfill";
import { ezToast, ezAlert } from "./ezq";
import {
  WindowController,
  init_notification_counter,
  inc_notification_counter,
  dec_notification_counter
} from "./utils";

const EventSource = NativeEventSource || EventSourcePolyfill;

export default root => {
  const source = new EventSource(root + "/events");
  const wc = new WindowController();
  const howl = new Howl({
    src: [
      root + "/themes/core/static/sounds/notification.webm",
      root + "/themes/core/static/sounds/notification.mp3"
    ]
  });

  init_notification_counter();

  function connect() {
    source.addEventListener(
      "notification",
      function(event) {
        var data = JSON.parse(event.data);
        wc.broadcast("notification", data);
        render(data);
      },
      false
    );
  }

  function disconnect() {
    if (source) {
      source.close();
    }
  }

  function render(data) {
    switch (data.type) {
      case "toast":
        inc_notification_counter();
        // Trim toast body to length
        let length = 50;
        let trimmed_content =
          data.content.length > length
            ? data.content.substring(0, length - 3) + "..."
            : data.content;
        let clicked = false;
        ezToast({
          title: data.title,
          body: trimmed_content,
          onclick: function() {
            ezAlert({
              title: data.title,
              body: data.content,
              button: "Понятно!",
              success: function() {
                clicked = true;
                dec_notification_counter();
              }
            });
          },
          onclose: function() {
            if (!clicked) {
              dec_notification_counter();
            }
          }
        });
        break;
      case "alert":
        inc_notification_counter();
        ezAlert({
          title: data.title,
          body: data.content,
          button: "Понятно!",
          success: function() {
            dec_notification_counter();
          }
        });
        break;
      case "background":
        inc_notification_counter();
        break;
      default:
        inc_notification_counter();
        break;
    }

    if (data.sound) {
      howl.play();
    }
  }

  wc.notification = function(data) {
    render(data);
  };

  wc.masterDidChange = function() {
    if (this.isMaster) {
      connect();
    } else {
      disconnect();
    }
  };
};
