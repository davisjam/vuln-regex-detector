
(function () {
  /**
   * Fast UUID generator, RFC4122 version 4 compliant.
   * Modified to use crypto.getRandomValues if available.
   * author Jeff Ward (jcward.com).
   * license MIT license
   * link http://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid-in-javascript/21963136#21963136
   **/
  var UUID = (function() {
    var self = {};
    var lut = []; for (var i=0; i<256; i++) { lut[i] = (i<16?'0':'')+(i).toString(16); }
    var numGen = (typeof(window.crypto) != 'undefined' && typeof(window.crypto.getRandomValues) != 'undefined') ?
      function() {var buf = new Uint32Array(4);window.crypto.getRandomValues(buf);return buf;} :
      function() {return [Math.random()*0xffffffff|0,Math.random()*0xffffffff|0,Math.random()*0xffffffff|0,Math.random()*0xffffffff|0];};

    self.generate = function() {
      var d = numGen();
      return lut[d[0]&0xff]+lut[d[0]>>8&0xff]+lut[d[0]>>16&0xff]+lut[d[0]>>24&0xff]+'-'+
        lut[d[1]&0xff]+lut[d[1]>>8&0xff]+'-'+lut[d[1]>>16&0x0f|0x40]+lut[d[1]>>24&0xff]+'-'+
        lut[d[2]&0x3f|0x80]+lut[d[2]>>8&0xff]+'-'+lut[d[2]>>16&0xff]+lut[d[2]>>24&0xff]+
        lut[d[3]&0xff]+lut[d[3]>>8&0xff]+lut[d[3]>>16&0xff]+lut[d[3]>>24&0xff];
    };
    return self;
  })(),
    initAutofill = function () {
      var uuid = UUID.generate(),
        host = 'https://www.linkedin.com',
        inFormScript = document.querySelector('script[type="IN/Form2"]'),
        autofillFrame = document.createElement('iframe'),
        frameSource = host + '/autofill/',
        formToFill,
        sendEvent = function (eventType, data) {
          var url = host + '/autofill/track/',
            request;

          data = data ? data : {};

          data.eventType = eventType;
          data.uuid = uuid;
          data = JSON.stringify(data);

          if (window.navigator && window.navigator.sendBeacon && window.Blob) {
            window.navigator.sendBeacon(url, new window.Blob([data], {
              type: 'text/plain'
            }));
          } else {
            request = new XMLHttpRequest();
            request.withCredentials = true;
            request.open('POST', url, true);
            request.setRequestHeader('Content-type', 'text/plain');

            request.send(data);
          }
        },
        renderIframe = function() {
          var frameWrapperOuter = document.createElement('span'),
            frameWrapperInner = document.createElement('span');

          frameWrapperOuter.setAttribute('class', 'IN-widget');
          frameWrapperOuter.setAttribute('style', 'line-height: 1; vertical-align: baseline; display: inline-block;');

          frameWrapperInner.setAttribute('style', 'padding: 0 !important; margin: 0 !important; text-indent: 0 !important; display: inline-block !important; vertical-align: baseline !important; font-size: 1px !important;');
          frameWrapperInner.appendChild(autofillFrame);

          frameWrapperOuter.appendChild(frameWrapperInner);

          autofillFrame.setAttribute('frameborder', '0');
          autofillFrame.setAttribute('style', 'width: 171px; height: 33px; display: inline-block;');
          autofillFrame.setAttribute('title', 'LinkedIn auto fill')
          autofillFrame.addEventListener('load', autofillLoadListener, false);
          autofillFrame.src = frameSource;

          window.addEventListener('message', function(event) {
            if (event.origin !== host) {
              return;
            }

            var message,
                rawData,
                data = {},
                key,
                newKey,
                keyMap = {},
                fieldsFilled = [];

            try {
              message = JSON.parse(event.data);
              if (message.type === 'formData') {
                rawData = message.data;
              } else if (message.type === 'reload') {
                autofillFrame.src = frameSource;
                return;
              } else if (message.type === 'size') {
                autofillFrame.style.height = message.data.height;
                return;
              } else {
                return;
              }
            } catch (e) {
              return;
            }

            for (key in rawData) {
              if (rawData.hasOwnProperty(key)) {
                newKey = inFormScript.getAttribute('data-field-' + key);

                if (newKey && newKey.length > 0) {
                  data[newKey.toLowerCase()] = rawData[key];
                  keyMap[newKey.toLowerCase()] = key;
                } else {
                  data[key] = rawData[key];
                  keyMap[key] = key;
                }
              }
            }

            [].slice.call(formToFill.elements).filter(function (element) {
              var nodeName = element.nodeName.toLowerCase(),
                  type = element.getAttribute('type');

              if(!nodeName || (nodeName !== 'input' && nodeName !== 'select' && nodeName !== 'textarea')) {
                return false;
              }

              return !(type && type.length > 0 && type.trim().toLowerCase() === 'hidden');
            }).forEach(function (element) {
              var attributeList = [
                'data-in-profile',
                'placeholder',
                'name',
                'id'
              ];

              attributeList.some(function (attributeName) {
                var attr = element.hasAttribute(attributeName) ? element.getAttribute(attributeName).toLowerCase() : false,
                    options;

                if (attr && data.hasOwnProperty(attr)) {
                  if(element.nodeName.toLowerCase() === 'select') {
                    options = element.getElementsByTagName('option');

                    [].slice.call(options).some(function(option) {
                      var value = data[attr].toLowerCase();
                      if (option.value && option.value.toLowerCase() === value) {
                        option.selected = true;
                        return true;
                      }
                    });
                  } else {
                    element.value = data[attr];
                  }

                  fieldsFilled.push(keyMap[attr]);
                  return true;
                }
              });
            });

            sendEvent('click', {
              fieldsFilled: fieldsFilled
            });
          }, false);

          inFormScript.parentElement.insertBefore(frameWrapperOuter, inFormScript);
        },
        autofillLoadListener = function() {
          autofillFrame.removeEventListener('load', autofillLoadListener);
          sendEvent('impression');

          formToFill.addEventListener('submit', function () {
            sendEvent('submit');
          });
        };

      if (inFormScript) {
        formToFill = document.getElementById(inFormScript.getAttribute('data-formid'));

        if (!formToFill) {
          formToFill = document.querySelector('[data-autofill-form-id="' + inFormScript.getAttribute('data-formid') + '"]');
        }

        if (!formToFill) {
          formToFill = document.getElementById(inFormScript.getAttribute('data-form'));
        }

        if (!formToFill) {
          formToFill = document.querySelector('[data-autofill-form-id="' + inFormScript.getAttribute('data-form') + '"]');
        }
      }

      // Only render the iframe if there is an actual form to fill
      if (formToFill && formToFill.nodeName.toLowerCase() === 'form') {
        renderIframe();
      }
    };

  if (document.readyState === 'complete') {
    initAutofill();
  } else {
    window.addEventListener('load', initAutofill, false);
  }
}());
