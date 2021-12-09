const {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse
} = require('@simplewebauthn/server')
const base64url = require('base64url')
const jwt = require('jsonwebtoken')

// mongoose models
const User = require('../models/User')

const HTTP_PROTO = process.env.HTTP_PROTO
const RP_ID = process.env.RP_ID || 'localhost'

// RP_ID_PORT must match the incoming request, also in prod env i.e. GCP Cloudrun no port is needed since it is not visible in the req frwd
// having one included will cause a mismatch and fail the assertion
// make sure to include the semicolon : in rp id port
const RP_PORT = process.env.RP_PORT || ''
// The expected origin of the request. It should match where the req is coming from.
//TODO as this is a multi-tenant app, the expected origin should be a map/array of acceptable clients origins that is pulled from DB to cache
//const expectedOrigin = `${HTTP_PROTO}${RP_ID}${RP_PORT}`
const expectedOrigin = process.env.EXPECTED_ORIGIN
console.log('expectedOrigin: ' + expectedOrigin);

// lets warn if run on http, should only be done in dev
if (HTTP_PROTO === "http://"){
  console.warn('\x1b[31m%s\x1b[0m', 'Warning: Service is on unsecured HTTP. Make sure to set your .env HTTP_PROTO variable')
}
if (HTTP_PROTO !=="https://" && HTTP_PROTO!== "http://") {
  throw new Error('No HTTP Protocol is set. Check your .env variable for "HTTP_PROTO"');
}
if (HTTP_PROTO !=='https://' && process.env.NODE_ENV === 'production')
{
  throw new Error('HTTPS must be used for production')
}


const getAttestationOptions = async (req, res) => {
  try {
    const { name, email } = req.body

    const existingUser = await User.findOne({ email })

    if (existingUser && existingUser.verifiedAtLeastOnce) {
      return res.status(500).json({ success: false, message: 'User already registered' })
    }

    let user = null

    if (existingUser && !existingUser.verifiedAtLeastOnce) {
      user = existingUser
    } else {
      const userDoc = new User({
        name,
        email,
        currentChallenge: 'no challenge added',
        devices: [],
        verifiedAtLeastOnce: false
      })

      user = await userDoc.save()
    }

    const opts = {
      rpName: 'Authmo',
      rpID: RP_ID,
      userID: user._id,
      userName: user.name,
      timeout: 60000,
      attestationType: 'indirect',
      excludeCredentials: user.devices.map((device) => ({
        id: device.credentialID,
        type: 'public-key',
        transports: []
      })),
      authenticatorSelection: {
        userVerification: 'preferred',
        requireResidentKey: false,
        authenticatorAttachment: ['platform']
      }
    }

    const options = generateAttestationOptions(opts)

    user.currentChallenge = options.challenge

    await user.save()

    res
      .status(200)
      .json({ success: true, data: { attestationOptions: options, userId: user._id } })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success: false, error: err.message })
  }
}

const getAttestationOptionsForExistingUser = async (req, res) => {
  try {
    const existingUser = await User.findOne({ _id: req.user._id })

    if (!existingUser) {
      return res.status(500).json({ success: false, message: 'User not found' })
    }

    let user = existingUser

    const opts = {
      rpName: 'Authmo',
      rpID: RP_ID,
      userID: user._id,
      userName: user.name,
      timeout: 60000,
      attestationType: 'indirect',
      excludeCredentials: user.devices.map((device) => ({
        id: device.credentialID,
        type: 'public-key',
        transports: ['internal']
      })),
      authenticatorSelection: {
        userVerification: 'preferred',
        requireResidentKey: false
      }
    }

    const options = generateAttestationOptions(opts)

    user.currentChallenge = options.challenge

    await user.save()

    res.status(200).json({ success: true, data: { attestationOptions: options } })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success: false, error: err.message })
  }
}

const verifyAttestation = async (req, res) => {
  try {
    const { userId, attestation } = req.body

    const user = await User.findOne({ _id: userId })

    const expectedChallenge = user.currentChallenge

    const opts = {
      credential: attestation,
      expectedChallenge: expectedChallenge,
      expectedOrigin,
      expectedRPID: RP_ID
    }

    const verification = await verifyAttestationResponse(opts)

    const { verified, attestationInfo } = verification

    if (verified && attestationInfo) {
      const { credentialPublicKey, credentialID, counter } = attestationInfo

      const existingDevice = user.devices.find(
        (device) => device.credentialID === credentialID
      )

      if (existingDevice) {
        return res
          .status(500)
          .json({ success: false, message: 'This authenticator already exists!' })
      }

      const newDevice = {
        credentialID,
        credentialPublicKey,
        counter
      }

      user.devices.push(newDevice)
      user.verifiedAtLeastOnce = true

      await user.save()
    }

    res.status(200).json({ success: true, data: verified })
  } catch (err) {
    console.log(err)
    return res.status(500).json({ success: false, error: err.message })
  }
}

const getAssertionOptions = async (req, res) => {
  try {
    const { email } = req.body

    const user = await User.findOne({ email })

    if (!user || !user.verifiedAtLeastOnce) {
      return res
        .status(404)
        .json({ success: false, message: 'No user with this email found' })
    }

    const opts = {
      allowCredentials: user.devices.map((device) => ({
        id: device.credentialID,
        type: 'public-key',
        transports: ['internal']
      })),
      userVerification: 'preferred',
      timeout: 60000,
      RP_ID
    }

    const options = generateAssertionOptions(opts)

    user.currentChallenge = options.challenge
    await user.save()

    res.status(200).json({ success: true, data: { assertionOptions: options, userId: user._id } })
  } catch (err) {
    console.log(err)
    return res.status(500).json({ success: false, error: err.message })
  }
}

const verifyAssertion = async (req, res) => {
  try {
    const { userId, assertion } = req.body

    const user = await User.findOne({ _id: userId })

    const expectedChallenge = user.currentChallenge

    const bodyCredIDBuffer = base64url.toBuffer(assertion.rawId)

    const dbAuthenticator = user.devices.find((device) =>
      device.credentialID.equals(bodyCredIDBuffer)
    )

    if (!dbAuthenticator) {
      return res
        .status(500)
        .json({ success: false, message: 'Could not find an authenticator match' })
    }

    const opts = {
      credential: assertion,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: RP_ID,
      authenticator: dbAuthenticator
    }

    const verification = verifyAssertionResponse(opts)

    const { verified, assertionInfo } = verification

    if (!verified) {
      return res.status(500).json({ success: false, message: 'Verification failed!' })
    }

    dbAuthenticator.counter = assertionInfo.newCounter

    user.devices = user.devices.map((device) =>
      device.credentialID.equals(bodyCredIDBuffer) ? dbAuthenticator : device
    )

    let updatedUser = await user.save()

    updatedUser = {
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email
    }

    const token = jwt.sign(updatedUser, process.env.TOKEN_SECRET, { expiresIn: '5d' })

    res.status(200).json({ success: true, data: { token, user: updatedUser } })
  } catch (err) {
    console.log(err)
    return res.status(500).json({ success: false, error: err.message })
  }
}

module.exports = {
  getAttestationOptions,
  verifyAttestation,
  getAssertionOptions,
  verifyAssertion,

  getAttestationOptionsForExistingUser
}
