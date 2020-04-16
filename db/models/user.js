'use strict';
module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
    emailAddress: DataTypes.STRING(255),
    firstName: DataTypes.STRING(50),
    lastName: DataTypes.STRING(50),
    hashedPassword: DataTypes.STRING.BINARY
  }, {});
  User.associate = function(models) {
    // associations can be defined here
  };
  return User;
};