package main

// Authenticate will return true if username is one of user{0,1,2,3} and
// password is pass.
func Authenticate(username, password string) (bool, error) {
	if username == "user0" || username == "user1" || username == "user2" || username == "user3" {
		if password == "pass" {
			return true, nil
		}
		return false, nil
	}
	return false, nil
}
