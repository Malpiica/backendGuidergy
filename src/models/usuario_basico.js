const { Model } = require('sequelize');
const bcrypt = require('bcryptjs');

module.exports = (sequelize, DataTypes) => {
  class UsuarioBasico extends Model {
    static associate(models) {
      UsuarioBasico.belongsTo(models.Administrador, {
        foreignKey: 'id_administrador',
        as: 'administrador'
      });
      UsuarioBasico.hasMany(models.Tarifa, {
        foreignKey: 'id_usuario_basico',
        as: 'tarifas'
      });
    }

    async validPassword(password) {
      return await bcrypt.compare(password, this.password);
    }
  }

  UsuarioBasico.init({
    id_usuario_basico: {
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
    id_administrador: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'administrador',
        key: 'id_administrador'
      }
    }
  }, {
    sequelize,
    modelName: 'UsuarioBasico',
    tableName: 'usuario_basico',
    timestamps: false,
    hooks: {
      beforeCreate: async (usuario) => {
        if (usuario.password) {
          const salt = await bcrypt.genSalt(10);
          usuario.password = await bcrypt.hash(usuario.password, salt);
        }
      },
      beforeUpdate: async (usuario) => {
        if (usuario.changed('password')) {
          const salt = await bcrypt.genSalt(10);
          usuario.password = await bcrypt.hash(usuario.password, salt);
        }
      }
    }
  });

  return UsuarioBasico;
};