module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'CrowdStrike Falcon X Intel',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'CSTKX',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'Displays enrichment data related to various indicator types from the Crowdstrike Falcon X Indicators API.',
  entityTypes: ['MD5', 'SHA1', 'SHA256', 'email', 'IPv4', 'domain'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/crowdstrike.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  defaultColor: 'light-pink',
  block: {
    component: {
      file: './components/crowdstrike-block.js'
    },
    template: {
      file: './templates/crowdstrike-block.hbs'
    }
  },
  summary: {
    component: {
      file: './components/crowdstrike-summary.js'
    },
    template: {
      file: './templates/crowdstrike-summary.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the STAXX integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the STAXX integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the STAXX integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the STAXX integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: ''
  },
  logging: {
    // directory is relative to the this integrations directory
    // e.g., if the integration is in /app/polarity-server/integrations/virustotal
    // and you set directoryPath to be `integration-logs` then your logs will go to
    // `/app/polarity-server/integrations/integration-logs`
    // You can also set an absolute path.  If you set an absolute path you must ensure that
    // the directory you specify is writable by the `polarityd:polarityd` user and group.

    //directoryPath: '/var/log/polarity-integrations',
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'url',
      name: 'Crowdstrike API URL',
      description:
        'The REST API URL for your Crowdstrike instance which should include the schema (i.e., http, https) and port if required.',
      default: 'https://api.crowdstrike.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'id',
      name: 'Client ID',
      description: 'The Client ID to use to connect to Crowdstrike.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'secret',
      name: 'Client Secret',
      description: 'The secret associated with the Client ID.',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'minimumConfidence',
      name: 'Minimum Confidence',
      description: 'The minimum malicious confidence level required for indicators to be displayed',
      default: {
        value: 'medium',
        display: 'Medium'
      },
      type: 'select',
      options: [
        {
          value: 'unverified',
          display: 'Unverified'
        },
        {
          value: 'low',
          display: 'Low'
        },
        {
          value: 'medium',
          display: 'Medium'
        },
        {
          value: 'high',
          display: 'High'
        }
      ],
      multiple: false,
      userCanEdit: true,
      adminOnly: false
    }
  ]
};
