const { Model } = require('sequelize');
const bcrypt = require('bcryptjs');

module.exports = (sequelize, DataTypes) => {
  class Administrador extends Model {
    static associate(models) {
      Administrador.belongsTo(models.Maestro, {
        foreignKey: 'id_maestro',
        as: 'maestro'
      });
      Administrador.belongsToMany(models.Comercializadora, {
        through: 'administrador_comercializadora',
        foreignKey: 'id_administrador',
        otherKey: 'id_comercializadora',
        as: 'comercializadoras'
      });
      Administrador.hasMany(models.UsuarioBasico, {
        foreignKey: 'id_administrador',
        as: 'usuarios'
      });
      Administrador.hasMany(models.TarifaConsultoria, {
        foreignKey: 'id_administrador',
        as: 'tarifas'
      });
    }

    async validPassword(password) {
      return await bcrypt.compare(password, this.password);
    }
  }

  Administrador.init({
    id_administrador: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    titular: {
      type: DataTypes.STRING(100),
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    telefono: {
      type: DataTypes.STRING(20),
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    nif_cif: {
      type: DataTypes.STRING(20),
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
    direccion: {
      type: DataTypes.TEXT,
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    cp: {
      type: DataTypes.STRING(10),
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    localidad: {
      type: DataTypes.STRING(100),
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    provincia: {
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
    password: {
      type: DataTypes.STRING(255),
      allowNull: false,
      validate: {
        notEmpty: true,
        len: [6, 255]
      }
    },
    margen: {
      type: DataTypes.FLOAT,
      allowNull: false,
      validate: {
        isFloat: true
      }
    },
    id_maestro: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'maestro',
        key: 'id_maestro'
      }
    }
  }, {
    sequelize,
    modelName: 'Administrador',
    tableName: 'administrador',
    timestamps: false,
    hooks: {
      beforeCreate: async (administrador) => {
        if (administrador.password) {
          const salt = await bcrypt.genSalt(10);
          administrador.password = await bcrypt.hash(administrador.password, salt);
        }
      },
      beforeUpdate: async (administrador) => {
        if (administrador.changed('password')) {
          const salt = await bcrypt.genSalt(10);
          administrador.password = await bcrypt.hash(administrador.password, salt);
        }
      }
    }
  });

  return Administrador;
};