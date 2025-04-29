const { Model } = require('sequelize');
const bcrypt = require('bcryptjs');

module.exports = (sequelize, DataTypes) => {
  class Maestro extends Model {
    static associate(models) {
      Maestro.hasMany(models.Comercializadora, {
        foreignKey: 'id_maestro',
        as: 'comercializadoras'
      });
      Maestro.hasMany(models.Administrador, {
        foreignKey: 'id_maestro',
        as: 'administradores'
      });
    }

    async validPassword(password) {
      return await bcrypt.compare(password, this.password);
    }
  }

  Maestro.init({
    id_maestro: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    nombre: {
      type: DataTypes.STRING(100),
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    apellidos: {
      type: DataTypes.STRING(100),
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    username: {
      type: DataTypes.STRING(50),
      allowNull: false,
      unique: true,
      validate: {
        notEmpty: true
      }
    },
    email: {
      type: DataTypes.STRING(100),
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true
      }
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: false,
      validate: {
        notEmpty: true,
        len: [6, 255]
      }
    }
  }, {
    sequelize,
    modelName: 'Maestro',
    tableName: 'maestro',
    timestamps: false,
    hooks: {
      beforeCreate: async (maestro) => {
        if (maestro.password) {
          const salt = await bcrypt.genSalt(10);
          maestro.password = await bcrypt.hash(maestro.password, salt);
        }
      },
      beforeUpdate: async (maestro) => {
        if (maestro.changed('password')) {
          const salt = await bcrypt.genSalt(10);
          maestro.password = await bcrypt.hash(maestro.password, salt);
        }
      }
    }
  });

  return Maestro;
};