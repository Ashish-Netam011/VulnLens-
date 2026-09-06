// Structural fixture: object and class methods.

const service = {
  getUser(id) {
    return db.find(id);
  },
  async deleteUser(id) {
    return db.remove(id);
  }
};

class UserService {
  findById(id) {
    return this.db.query(id);
  }
  static create() {
    return new UserService();
  }
}
