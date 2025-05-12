import {verifyPasswd} from '@gallolabs/passwd-verifier'
import { PureAbility, RawRule, subject } from '@casl/ability'
import {flatten,omit} from 'lodash-es'

interface Authorizable {
	authorizations?: RawRule[]
	roles?: Array<string | Role>
}

export interface User extends Authorizable {
	login: string
	password: string
}

export interface Guest extends Authorizable {}

export interface Role {
	name: string
	extends?: Array<string | Role>
	authorizations?: RawRule[]
}

export class AuthenticationError extends Error {
    name = 'AuthenticationError'
}

export class AuthorizationError extends Error {
    name = 'AuthorizationError'
}

export interface AuthOpts {
	roles?: Role[]
	users: User[]
	guest?: Guest
}

export default class Auth {
	protected roles: Role[]
	protected users: User[]
	protected guest: Guest

	public constructor(opts: AuthOpts) {
		this.roles = opts.roles || []
		this.users = opts.users
		this.guest = opts.guest || {}
	}

	public async authenticate(login: string, password: string): Promise<Omit<User, 'password'> | false> {
		const user = this.users.find(u => u.login === login)

		if (!user) {
			await verifyPasswd('', '', {})
		} else {
			if (await verifyPasswd(password, user.password)) {
				return omit(user, 'password')
			}
		}

		return false
	}

	public async ensureAuthentication(login: string, password: string): Promise<Omit<User, 'password'>> {
		const user = await this.authenticate(login, password)

		if (!user) {
			throw new AuthenticationError
		}

		return user
	}

	public async isAuthorized(user: string | null | Authorizable, action: string, subjectType: string, subjectParams: object = {}): Promise<boolean> {
		if (user === undefined) {
			throw new Error('Undefined user is not allowed by security')
		}

		if (typeof user === 'string') {
			const foundUser = this.users.find(u => u.login === user)

			if (!foundUser) {
				throw new Error('User not found')
			}

			user = foundUser
		}

		if (user === null) {
			user = this.guest
		}

		const userRoles = (user.roles || []).map(role => {
			if (typeof role === 'string') {
				const foundRole = this.roles.find(r => r.name === role)

				if (!foundRole) {
					throw new Error('Unknown role ' + role)
				}

				role = foundRole
			}

			return role
		})

		const userRolesAuthorizations = flatten(userRoles.map(role => role.authorizations || []))
		const userAuthorizations = user.authorizations || []

		const ability = new PureAbility([...userRolesAuthorizations, ...userAuthorizations]);

		return ability.can(action, subject(subjectType, subjectParams))

	}

	public async ensureAuthorization(user: string | null | Authorizable, action: string, subjectType: string, subjectParams: object = {}): Promise<true> {
		if (!await this.isAuthorized(user, action, subjectType, subjectParams)) {
			throw new AuthorizationError
		}

		return true
	}

}
