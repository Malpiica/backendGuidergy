const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class Comercializadora extends Model {
    static associate(models) {
      Comercializadora.belongsTo(models.Maestro, {
        foreignKey: 'id_maestro',
        as: 'maestro'
      });
      Comercializadora.belongsToMany(models.Administrador, {
        through: 'administrador_comercializadora',
        foreignKey: 'id_comercializadora',
        otherKey: 'id_administrador',
        as: 'administradores'
      });
    }
  }

  Comercializadora.init({
    id_comercializadora: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    nombre: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true,
      validate: {
        notEmpty: true
      }
    },
    archivo: {
      type: DataTypes.TEXT,
      allowNull: false,
      validate: {
        notEmpty: true
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
    modelName: 'Comercializadora',
    tableName: 'comercializadora',
    timestamps: false
  });

  return Comercializadora;
};